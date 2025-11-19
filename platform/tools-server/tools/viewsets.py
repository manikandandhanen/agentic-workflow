from __future__ import annotations

import hashlib
import io
import json as _json
import logging

import requests
from django.core.cache import cache
from django.db import transaction
from django.db.models import F
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter

from accounts.auth import BearerServiceTokenAuthentication, ServicePrincipal
from accounts.models import Team, Tenant
from tools.cache_keys import cap_snapshot_key
from tools.models import ApiProvider, NormalizedCapability, RiskLevel, SchemaSource
from tools.permissions import IsTenantMemberOrServiceToken
from tools.serializers import (
    ApiProviderSerializer,
    NormalizeResultSerializer,
    SchemaDiscoverSerializer,
    SchemaUploadSerializer,
    CapabilitySnapshotSerializer,
)
from tools.utils.openapi_normalizer import normalize_and_persist, normalize_openapi
from tools.utils.helpers import get_create_by_info_from_request

logger = logging.getLogger(__name__)

@extend_schema_view(
    retrieve=extend_schema(
        parameters=[OpenApiParameter("id", type=int, location=OpenApiParameter.PATH, description="ID of the ApiProvider")]
    ),
    update=extend_schema(
        parameters=[OpenApiParameter("id", type=int, location=OpenApiParameter.PATH, description="ID of the ApiProvider")]
    ),
    partial_update=extend_schema(
        parameters=[OpenApiParameter("id", type=int, location=OpenApiParameter.PATH, description="ID of the ApiProvider")]
    ),
    destroy=extend_schema(
        parameters=[OpenApiParameter("id", type=int, location=OpenApiParameter.PATH, description="ID of the ApiProvider")]
    ),
)
class ApiProviderViewSet(viewsets.ModelViewSet):
    """
    /tools/providers/  (list, create)
    /tools/providers/{id}/ (retrieve, update, partial_update)
    """
    serializer_class = ApiProviderSerializer
    permission_classes = [IsTenantMemberOrServiceToken]

    def get_queryset(self):
        user = self.request.user
        return ApiProvider.objects.filter(tenant=user.tenant).select_related("tenant", "owner_team")

    def perform_create(self, serializer):
        serializer.save()  # tenant injected in serializer.create()


@extend_schema_view(
    retrieve=extend_schema(
        parameters=[OpenApiParameter("id", type=int, location=OpenApiParameter.PATH, description="ID of the SchemaSource")]
    )
)
class SchemaSourceViewSet(mixins.CreateModelMixin,
                          mixins.RetrieveModelMixin,
                          mixins.ListModelMixin,
                          viewsets.GenericViewSet):
    """
    /tools/schemas/ (POST upload intake, GET list)
    /tools/schemas/{id}/ (GET)
    /tools/schemas/discover/ (POST) -> fetch from URL and store blob
    """
    serializer_class = SchemaUploadSerializer
    permission_classes = [IsTenantMemberOrServiceToken]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def create(self, request, *args, **kwargs):
        """
        Upload a schema file (.json/.yaml). On success:
        - stores the SchemaSource
        - computes sha256 & meta
        - optionally normalizes into capabilities when `auto_normalize` flag present
        Returns {"schema": <SchemaSource>, "normalize": <NormalizeResult?>}
        """
        # Enforce file type (json/yaml) when blob present
        blob = request.FILES.get("blob")
        if blob:
            fname = (blob.name or "").lower()
            if not (fname.endswith(".json") or fname.endswith(".yaml") or fname.endswith(".yml")):
                return Response({"detail": "Only .json, .yaml, or .yml files are allowed."},
                                status=status.HTTP_400_BAD_REQUEST)

        # create the SchemaSource 
        resp = super().create(request, *args, **kwargs)
        logger.info(
            "Uploading schema source for tenant=%s by user=%s response status code=%s",
            request.user.tenant.slug,
            request.user.email,
            resp.status_code,
        )
        if resp.status_code != 201:
            return resp

        # compute hash if not already set by serializer via compute_hash_and_meta
        src_id = resp.data["id"]
        src = self.get_queryset().get(pk=src_id)

        out = {
            "schema": SchemaUploadSerializer(instance=src, context={"request": request}).data,
        }

        auto_normalize_param = request.query_params.get("auto_normalize", request.data.get("auto_normalize"))
        print(auto_normalize_param, '>>>>>>>>>>>>>>>> auto_normalize_param')
        auto_normalize = True  # Default to True
        if auto_normalize_param is not None:
            auto_normalize = str(auto_normalize_param).strip().lower() in {"1", "true", "yes", "on"}

        if auto_normalize:
            logger.info(
                "Auto-normalizing uploaded schema source id=%s tenant=%s provider=%s",
                src.id,
                src.tenant.slug,
                src.provider.name,
            )
            try:
                result = normalize_and_persist(request, src)
            except ValueError as e:
                return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)
            out["normalize"] = NormalizeResultSerializer(result).data

        return Response(out, status=status.HTTP_201_CREATED)

    def get_queryset(self):
        user = self.request.user
        return SchemaSource.objects.filter(tenant=user.tenant).select_related("tenant", "provider", "created_by")

    @action(detail=False, methods=["post"], url_path="discover")
    def discover(self, request, *args, **kwargs):
        """
        Pull a schema from a remote URL and persist as a SchemaSource with a blob.
        - Honors optional If-None-Match via `etag` to avoid re-downloads.
        - Enforces provider's domain allowlist implicitly (host must match).
        """
        ser = SchemaDiscoverSerializer(data=request.data, context={"request": request})
        ser.is_valid(raise_exception=True)
        provider = ser.validated_data["provider"]
        kind = ser.validated_data["kind"]
        url = ser.validated_data["url"]
        etag = ser.validated_data.get("etag", "")

        # Basic domain allowlist enforcement
        from urllib.parse import urlparse
        host = urlparse(url).hostname
        allowed = set(provider.domain_allowlist if isinstance(provider.domain_allowlist, list)
                      else [d.strip() for d in provider.domain_allowlist.split(",") if d.strip()])
        if host not in allowed:
            return Response(
                {"detail": f"Host '{host}' is not in provider's allowlist."},
                status=status.HTTP_400_BAD_REQUEST
            )

        headers = {}
        if etag:
            headers["If-None-Match"] = etag

        try:
            resp = requests.get(url, headers=headers, timeout=20)
        except requests.RequestException as e:
            return Response({"detail": f"Failed to fetch schema: {e}"}, status=status.HTTP_502_BAD_GATEWAY)

        if resp.status_code == 304:
            return Response({"detail": "Not modified", "etag": etag}, status=status.HTTP_304_NOT_MODIFIED)

        if resp.status_code >= 400:
            return Response({"detail": f"Upstream returned {resp.status_code}"}, status=status.HTTP_502_BAD_GATEWAY)

        content = resp.content or b""
        content_type = resp.headers.get("Content-Type", "application/octet-stream")
        new_etag = resp.headers.get("ETag", "")

        # Build an in-memory file for FileField
        filename = url.split("/")[-1] or f"{kind}.json"
        memfile = io.BytesIO(content)
        memfile.name = filename  # Django File upload machinery uses .name
        from django.core.files.uploadedfile import InMemoryUploadedFile
        upload = InMemoryUploadedFile(
            file=memfile,
            field_name="blob",
            name=filename,
            content_type=content_type,
            size=len(content),
            charset=None,
        )

        # Create SchemaSource
        src = SchemaSource.objects.create(
            tenant=request.user.tenant,
            provider=provider,
            kind=kind,
            url=url,
            blob=upload,
            etag=new_etag or "",
            created_by=request.user,
            content_type=content_type,
            content_size=len(content),
        )
        # Compute hash
        src.compute_hash_and_meta()
        src.save(update_fields=["sha256", "content_type", "content_size", "updated_at"])

        # Auto-normalize + cache
        try:
            result = normalize_and_persist(request, src)
        except ValueError as e:
            return Response({"detail": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        # Build combined output
        out = {
            "schema": SchemaUploadSerializer(instance=src, context={"request": request}).data,
            "normalize": NormalizeResultSerializer(result).data,
        }
        return Response(out, status=status.HTTP_201_CREATED)

        # out = SchemaUploadSerializer(instance=src, context={"request": request}).data
        # return Response(out, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["post"], url_path="normalize")
    def normalize(self, request, pk=None, *args, **kwargs):
        """
        Normalize this SchemaSource (OpenAPI 3.x v1) into NormalizedCapability rows.
        - Determines next provider version (max + 1)
        - Creates capabilities disabled by default with LOW risk
        """
        src = self.get_object()
        if not src.blob:
            return Response({"detail": "SchemaSource has no uploaded blob to normalize."},
                            status=status.HTTP_400_BAD_REQUEST)

        with src.blob.open("rb") as f:
            raw = f.read()

        try:
            oas_ver, caps = normalize_openapi(src.provider, raw)
        except ValueError as e:
            return Response({"detail": f"Validation error: {e}"}, status=status.HTTP_400_BAD_REQUEST)

        # Determine next version for this provider
        qs = NormalizedCapability.objects.filter(provider=src.provider)
        next_version = (qs.order_by("-version").values_list("version", flat=True).first() or 0) + 1

        created = 0
        create_by, create_by_type, create_by_identifier = get_create_by_info_from_request(request)
        with transaction.atomic():
            for cap in caps:
                NormalizedCapability.objects.create(
                    tenant=request.user.tenant,
                    created_by=create_by,                                             
                    created_by_type=create_by_type,
                    created_by_identifier=create_by_identifier, 
                    provider=src.provider,
                    version=next_version,
                    name=cap["name"],
                    json_schema_in=cap["json_schema_in"],
                    json_schema_out=cap.get("json_schema_out"),
                    risk_level=RiskLevel.LOW,
                    enabled=False,
                    wire=cap.get("wire") or {},
                )
                created += 1

        payload = {
            "provider_id": str(src.provider_id),
            "version": next_version,
            "count_created": created,
            "openapi_version": oas_ver,
            "sample": list(caps[:5]),  # tiny preview
        }
        return Response(NormalizeResultSerializer(payload).data, status=status.HTTP_201_CREATED)


class CapabilitiesViewSet(viewsets.ViewSet):
    """
    GET /tools/api/<v1.0>/capabilities?tenant=<slug|id>&team=<slug|id>&active=true

    Returns a snapshot suitable for MCP:
    {
      "cap_set_id": <int>,        # monotonic-ish, derived from versions/rows
      "etag": "W/\"sha256:...\"",
      "capabilities": [
        {"name": "<provider.resource.action>", "version": <int>, "input_schema": {...}, "wire": {}}
      ]
    }

    Notes:
    - Active means NormalizedCapability.enabled=True
    - Team must have an AccessGrant pinned to the capability version
    - ETag stable over ordering; responds 304 to If-None-Match
    """
    permission_classes = [IsTenantMemberOrServiceToken]
    authentication_classes = [BearerServiceTokenAuthentication, JWTAuthentication]
    required_scope = "capabilities:read"

    @extend_schema(
        responses=CapabilitySnapshotSerializer,
        description="Get a snapshot of capabilities for a tenant and team."
    )
    def list(self, request):
        print('CapabilitiesViewSet.list called >>>>>>> ', request.user, request.user.__dict__)
        tenant = request.user.tenant if hasattr(request.user, "tenant") and request.user.tenant else None
        if isinstance(request.user, ServicePrincipal) and request.user.is_staff:
            # ServicePrincipal with is_staff can specify tenant via query param
            # print("SP is_staff detected, checking tenant query param...")
            tenant_slug = request.query_params.get("tenant")
            # print("Tenant slug from query param >>>>>>>>>>>>>>> :", tenant_slug)
            if tenant_slug:
                try:
                    tenant = Tenant.objects.get(slug=tenant_slug)
                except Tenant.DoesNotExist:
                    return Response({"detail": "Tenant not found."}, status=status.HTTP_404_NOT_FOUND)
        team_slug_or_id = request.query_params.get("team")
        team_id = None
        if str(team_slug_or_id).isdigit():
            try:
                team_id = Team.objects.get(tenant=tenant, id=int(team_slug_or_id)).id
            except Team.DoesNotExist:
                print(" >>>>>>>>>>>>>>> Team not found by ID:", team_slug_or_id, "and tenant: ", tenant)
                return Response({"detail": "Team not found."}, status=status.HTTP_404_NOT_FOUND)
        else:
            try:
                team_id = Team.objects.get(tenant=tenant, slug=team_slug_or_id).id
            except Team.DoesNotExist:
                return Response({"detail": "Team not found."}, status=status.HTTP_404_NOT_FOUND)

        active = request.query_params.get("active", "true").lower() in ("1", "true", "yes")
        key = cap_snapshot_key(tenant.id, team_id, active)

        cached = cache.get(key)
        inm = request.headers.get("If-None-Match", "").strip()

        if cached:
            etag = cached.get("etag")
            if etag and inm == etag:
                return Response({'key': key}, status=status.HTTP_304_NOT_MODIFIED, headers={"ETag": etag})
            # Serve from cache
            return Response(cached, status=status.HTTP_200_OK, headers={"ETag": cached.get("etag", "")})

        # Cache MISS: compute snapshot

        # Filter approved & enabled capabilities pinned to the team
        caps_qs = (
            NormalizedCapability.objects
            .filter(
                tenant=tenant,
                enabled=True if active else False,
                access_grants__team_id=team_id,
                access_grants__version=F("version"),
            )
            .select_related("provider")
            .order_by("provider__name", "name", "version", "id")
            .distinct()
        )

        caps = [
            {
                "name": f"{c.name}",             # provider.resource.action per normalizer
                "version": c.version,
                "input_schema": c.json_schema_in,
                "wire": c.wire or {},
            }
            for c in caps_qs
        ]

        # Compute a stable ETag over the snapshot content (names+versions+hash of schemas)
        # Avoid dumping full schemas into the hash one-by-one; do a small digest per cap.
        cap_digests = []
        for c in caps:
            h = hashlib.sha256()
            h.update(c["name"].encode("utf-8"))
            h.update(str(c["version"]).encode("utf-8"))
            h.update(_json.dumps(c["input_schema"], sort_keys=True, separators=(",", ":")).encode("utf-8"))
            h.update(_json.dumps(c.get("wire", {}), sort_keys=True, separators=(",", ":")).encode("utf-8"))
            cap_digests.append(h.hexdigest())
        list_digest = hashlib.sha256("".join(cap_digests).encode("utf-8")).hexdigest()
        etag = f'W/"sha256:{list_digest}"'

        max_ver = max((c["version"] for c in caps), default=0)
        cap_set_id = max_ver * 1_000_000 + len(caps)
        payload = {"cap_set_id": cap_set_id, "etag": etag, "capabilities": caps}

        # 60–120s cache to avoid staleness + 
        # signals will also invalidate
        cache.set(key, payload, timeout=120)

        if inm and inm == etag:
            return Response(status=status.HTTP_304_NOT_MODIFIED, headers={"ETag": etag})

        return Response(payload, status=status.HTTP_200_OK, headers={"ETag": etag})
