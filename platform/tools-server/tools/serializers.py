from __future__ import annotations

import json
from urllib.parse import urlparse

from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from tools.models import ApiProvider, SchemaSource, SchemaKind
from tools.utils.helpers import get_create_by_info_from_request

class CreatedByMixin:
    def set_created_by_related_fields(self, validated_data):
        created_by, created_by_type, created_by_identifier = get_create_by_info_from_request(self.context["request"])
        validated_data["created_by_type"] = created_by_type
        validated_data["created_by_identifier"] = created_by_identifier
        validated_data["created_by"] = created_by
        return validated_data

class RequireTenantMixin:
    def validate_tenant(self):
        user = self.context["request"].user
        if user.tenant_id is None:
            raise serializers.ValidationError(_("User must belong to a tenant."))

    def set_tenant(self, validated_data):
        self.validate_tenant()
        user = self.context["request"].user
        if user.tenant_id is not None:
            validated_data["tenant"] = user.tenant
        return validated_data

class ApiProviderSerializer(RequireTenantMixin, serializers.ModelSerializer):
    tenant = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = ApiProvider
        fields = [
            "id", "tenant", "name", "owner_team", "base_url",
            "auth_profile", "domain_allowlist", "status",
            "created_at", "updated_at",
        ]
        read_only_fields = ["id", "tenant", "created_at", "updated_at"]

    def validate(self, attrs):
        base_url = attrs.get("base_url") or getattr(self.instance, "base_url", None)
        owner_team = attrs.get("owner_team") or getattr(self.instance, "owner_team", None)
        if base_url:
            host = urlparse(base_url).hostname
            if not host:
                raise serializers.ValidationError({"base_url": _("Invalid base_url")})
        if owner_team and self.context["request"].user.tenant_id != owner_team.tenant_id:
            raise serializers.ValidationError({"owner_team": _("Owner team must be in your tenant.")})
        return attrs

    def create(self, validated_data):
        validated_data = self.set_tenant(validated_data)
        return super().create(validated_data)


class SchemaUploadSerializer(CreatedByMixin,
                             RequireTenantMixin, 
                             serializers.ModelSerializer):
    """
    Intake: upload file or paste JSON as a file-like (client can send multipart with 'blob' or raw JSON).
    """
    tenant = serializers.PrimaryKeyRelatedField(read_only=True)
    created_by = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = SchemaSource
        fields = [
            "id", "tenant", "provider", "kind", "url", "blob",
            "etag", "content_type", "content_size", "sha256",
            "created_by", "created_at",
        ]
        read_only_fields = ["id", "tenant", "etag", "content_type", "content_size", "sha256", "created_by", "created_at"]

    def validate(self, attrs):
        url = attrs.get("url")
        blob = attrs.get("blob")
        if not url and not blob:
            raise serializers.ValidationError(_("Provide either 'url' or 'blob'."))
        if url and blob:
            raise serializers.ValidationError(_("Provide only one of 'url' or 'blob'."))
        provider = attrs.get("provider")
        if provider and provider.tenant_id != self.context["request"].user.tenant_id:
            raise serializers.ValidationError({"provider": _("Provider must belong to your tenant.")})
        return attrs

    def create(self, validated_data):
        validated_data = self.set_tenant(validated_data)
        validated_data = self.set_created_by_related_fields(validated_data)
        obj: SchemaSource = super().create(validated_data)
        # Compute metadata (hash, content-type) for uploads
        if obj.blob:
            obj.compute_hash_and_meta()
            obj.save(update_fields=["sha256", "content_size", "content_type", "updated_at"])
        return obj


class SchemaDiscoverSerializer(serializers.Serializer):
    """
    Discovery: pull from URL and persist a SchemaSource with blob populated from the response.
    """
    provider = serializers.PrimaryKeyRelatedField(queryset=ApiProvider.objects.all())
    kind = serializers.ChoiceField(choices=SchemaKind.choices)
    url = serializers.URLField()
    etag = serializers.CharField(required=False, allow_blank=True)

    def validate_provider(self, provider: ApiProvider):
        req = self.context["request"]
        if provider.tenant_id != req.user.tenant_id:
            raise serializers.ValidationError(_("Provider must belong to your tenant."))
        return provider


class NormalizeResultSerializer(serializers.Serializer):
    provider_id = serializers.UUIDField()
    version = serializers.IntegerField()
    count_created = serializers.IntegerField()
    openapi_version = serializers.CharField()
    sample = serializers.ListField(child=serializers.DictField(), required=False)


class CapabilityOutSerializer(serializers.Serializer):
    name = serializers.CharField()
    version = serializers.IntegerField()
    input_schema = serializers.DictField()
    wire = serializers.DictField(required=False)

class CapabilitySnapshotSerializer(serializers.Serializer):
    cap_set_id = serializers.IntegerField()
    etag = serializers.CharField()
    capabilities = CapabilityOutSerializer(many=True)