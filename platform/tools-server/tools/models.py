from __future__ import annotations

import hashlib
import json
import mimetypes
import uuid
from urllib.parse import urlparse

from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.text import slugify
from django.db import models
from django.db.models.functions import Lower
from django.utils.translation import gettext_lazy as _
from core.mixins import TimeStampedModel
from core.storages import AzureMediaStorage

try:
    from django.contrib.postgres.fields import ArrayField
    HAS_ARRAYFIELD = True
except Exception:
    HAS_ARRAYFIELD = False


# ------------ Enums ------------

class ProviderStatus(models.TextChoices):
    DRAFT    = "draft",    _("Draft")
    ACTIVE   = "active",   _("Active")
    DISABLED = "disabled", _("Disabled")
    ARCHIVED = "archived", _("Archived")


class SchemaKind(models.TextChoices):
    OPENAPI    = "openapi",    _("OpenAPI 3.x")
    GRAPHQL    = "graphql",    _("GraphQL Introspection/SDL")
    ASYNCAPI   = "asyncapi",   _("AsyncAPI")
    GRPC       = "grpc",       _("gRPC / Protobuf")
    JSONSCHEMA = "jsonschema", _("Raw JSON Schema")


class AuthProfile(models.TextChoices):
    NONE        = "none",        _("None")
    OAUTH2_CC   = "oauth2_cc",   _("OAuth2 Client Credentials")
    API_KEY_HDR = "api_key_hdr", _("API Key (Header)")
    API_KEY_QS  = "api_key_qs",  _("API Key (Query)")
    BEARER_JWT  = "bearer_jwt",  _("Bearer JWT")
    MTLS        = "mtls",        _("mTLS")


class RiskLevel(models.TextChoices):
    LOW    = "low",    _("Low")
    MEDIUM = "medium", _("Medium")
    HIGH   = "high",   _("High")


class ExecStatus(models.TextChoices):
    SUCCESS          = "success",          _("Success")
    UPSTREAM_ERROR   = "upstream_error",   _("Upstream Error")
    POLICY_BLOCKED   = "policy_blocked",   _("Policy Blocked")
    RATE_LIMITED     = "rate_limited",     _("Rate Limited")
    VALIDATION_ERROR = "validation_error", _("Validation Error")
    TIMEOUT          = "timeout",          _("Timeout")


# ------------ Core entities ------------

class ApiProvider(TimeStampedModel):
    """
    Represents an external (or internal) API surface that will be normalized to capabilities.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey("accounts.Tenant", on_delete=models.CASCADE, related_name="api_providers")
    name = models.CharField(max_length=120)
    owner_team = models.ForeignKey("accounts.Team", on_delete=models.PROTECT, related_name="owned_providers")
    base_url = models.URLField(help_text=_("Base URL such as https://api.example.com"))
    auth_profile = models.CharField(max_length=20, choices=AuthProfile.choices, default=AuthProfile.NONE)
    status = models.CharField(max_length=10, choices=ProviderStatus.choices, default=ProviderStatus.DRAFT)

    # Allowed outbound domains for this provider (enforced in gateway)
    if HAS_ARRAYFIELD:
        domain_allowlist = ArrayField(models.CharField(max_length=255), default=list, blank=True)
    else:
        domain_allowlist = models.TextField(blank=True, default="", help_text=_("Comma-separated domains if ArrayField unavailable."))

    class Meta:
        unique_together = (("tenant", "name"),)
        indexes = [
            models.Index(fields=("tenant", "name")),
            models.Index(Lower("base_url"), name="api_provider_base_url_idx"),
        ]
        ordering = ("tenant__slug", "name")

    @property
    def slug(self) -> str:
        return f"{self.tenant.slug}:{slugify(self.name)}"

    def __str__(self):
        return f"{self.tenant.slug}:{self.name}"

    def clean(self):
        super().clean()
        # Ensure base_url hostname is included in allowlist
        host = urlparse(self.base_url).hostname
        if not host:
            raise ValidationError({"base_url": _("Invalid base URL")})
        if HAS_ARRAYFIELD:
            if self.domain_allowlist and host not in self.domain_allowlist:
                self.domain_allowlist = list(sorted(set(self.domain_allowlist + [host])))
        else:
            domains = [d.strip() for d in self.domain_allowlist.split(",") if d.strip()]
            if host not in domains:
                domains.append(host)
                self.domain_allowlist = ",".join(sorted(set(domains)))


def _schema_upload_path(instance: "SchemaSource", filename: str) -> str:
    return f"schemas/{instance.provider.slug}/{uuid.uuid4()}-{filename}"


class CreatedByType(models.TextChoices):
    USER   = "User",  _("User")
    SP  = "ServicePrincipal", _("ServicePrincipal")


class SchemaSource(TimeStampedModel):
    """
    Stores raw schema artifacts or references discovered from URLs.
    Either 'url' is set (for discovery sources) or 'blob' is set (for uploads).
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey("accounts.Tenant", on_delete=models.CASCADE, related_name="schema_sources")
    provider = models.ForeignKey(ApiProvider, on_delete=models.CASCADE, related_name="schema_sources")
    kind = models.CharField(max_length=20, choices=SchemaKind.choices)

    # Either URL or blob (FileField) must be set
    url = models.URLField(blank=True, null=True)    # this is the discovery URL
    blob = models.FileField(upload_to=_schema_upload_path, storage=AzureMediaStorage(), blank=True, null=True)

    # Metadata
    etag = models.CharField(max_length=200, blank=True, default="")
    content_type = models.CharField(max_length=120, blank=True, default="")
    content_size = models.BigIntegerField(default=0)
    sha256 = models.CharField(max_length=64, blank=True, default="")

    # User
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.PROTECT, 
        related_name="created_schema_sources",
        blank=True,
        null=True,
        help_text="Null if created by service principal")

    # SP
    created_by_type = models.CharField(
        max_length=24,
        choices=CreatedByType.choices,
        default=CreatedByType.USER
    )
    created_by_identifier = models.CharField(
        null=True,
        help_text="Email for user, or service token id:name for service principal"
    )

    class Meta:
        indexes = [
            models.Index(fields=("tenant", "provider")),
            models.Index(fields=("provider", "kind")),
        ]
        ordering = ("-created_at",)

    def __str__(self):
        return f"{self.provider.name}:{self.kind}:{self.id}"

    def clean(self):
        super().clean()
        if not self.url and not self.blob:
            raise ValidationError(_("Either url or blob must be provided."))
        if self.url and self.blob:
            raise ValidationError(_("Provide either url or blob, not both."))
        # Ensure tenant/provider tenant alignment
        if self.tenant_id != self.provider.tenant_id:
            raise ValidationError(_("Tenant mismatch between SchemaSource and ApiProvider."))

    def compute_hash_and_meta(self):
        if self.blob and hasattr(self.blob, "file"):
            # Compute sha256
            h = hashlib.sha256()
            for chunk in self.blob.chunks():
                h.update(chunk)
            self.sha256 = h.hexdigest()
            self.content_size = self.blob.size or 0
            if not self.content_type:
                guessed, _ = mimetypes.guess_type(self.blob.name)
                self.content_type = guessed or "application/octet-stream"


class NormalizedCapability(TimeStampedModel):
    DEFAULT_SCOPES = ["read"]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey("accounts.Tenant", on_delete=models.CASCADE, related_name="capabilities")
    provider = models.ForeignKey(ApiProvider, on_delete=models.CASCADE, related_name="capabilities")
    version = models.PositiveIntegerField(default=1)
    name = models.CharField(max_length=200)  # provider.resource.action
    json_schema_in = models.JSONField()
    json_schema_out = models.JSONField(blank=True, null=True)
    risk_level = models.CharField(max_length=10, choices=RiskLevel.choices, default=RiskLevel.LOW)
    enabled = models.BooleanField(default=True) # Default to enabled for the default read scope
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.PROTECT, 
        related_name="created_capabilities",
        blank=True,
        null=True,
        help_text="Null if created by service principal")
    created_by_type = models.CharField(
        max_length=24,
        choices=CreatedByType.choices,
        default=CreatedByType.USER
    )
    created_by_identifier = models.CharField(
        null=True,
        help_text="Email for user, or service token id:name for service principal"
    )
    # Example
    wire = models.JSONField(blank=True, null=True, help_text=_("Wire format details such as HTTP method, path, path_map, query_map headers."))

    class Meta:
        unique_together = (("provider", "version", "name"),)
        indexes = [
            models.Index(fields=("provider", "version")),
            models.Index(fields=("tenant", "enabled")),
        ]
        ordering = ("provider__name", "name", "version")


class AccessGrant(TimeStampedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    team = models.ForeignKey("accounts.Team", on_delete=models.CASCADE, related_name="access_grants")
    capability = models.ForeignKey(NormalizedCapability, on_delete=models.CASCADE, related_name="access_grants")
    version = models.PositiveIntegerField(help_text=_("Pinned capability version"), blank=True, null=True)
    scopes = models.JSONField(default=list, help_text=_("List of scope strings (e.g., ['read', 'write'])."))
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.PROTECT, 
        related_name="approved_access_grants",
        blank=True,
        null=True,
        help_text="Null if approved by service principal")
    approved_by_type = models.CharField(
        max_length=24,
        choices=CreatedByType.choices,
        default=CreatedByType.USER
    )
    approved_by_identifier = models.CharField(
        null=True,
        help_text="Email for user, or service token id:name for service principal"
    )
    expires_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        unique_together = (("team", "capability", "version"),)
        indexes = [
            models.Index(fields=("team", "expires_at")),
        ]

    def save(self, *args, **kwargs):
        if not self.version:
            self.version = self.capability.version
        super().save(*args, **kwargs)

class ExecutionLog(models.Model):
    """
    Execution logs can be high-volume; keep them lean (no auto_now fields).
    """
    id = models.BigAutoField(primary_key=True)
    tenant = models.ForeignKey("accounts.Tenant", on_delete=models.CASCADE, related_name="execution_logs")
    capability = models.ForeignKey(NormalizedCapability, on_delete=models.SET_NULL, null=True, blank=True, related_name="execution_logs")
    version = models.PositiveIntegerField()
    actor = models.CharField(max_length=200)  # user email or service principal id (hashed externally if needed)
    latency_ms = models.IntegerField()
    status = models.CharField(max_length=20, choices=ExecStatus.choices)
    pii_touched = models.BooleanField(default=False)
    error_kind = models.CharField(max_length=120, blank=True, default="")
    timestamp = models.DateTimeField(db_index=True)

    class Meta:
        indexes = [
            models.Index(fields=("tenant", "timestamp")),
            models.Index(fields=("status",)),
        ]
        ordering = ("-timestamp",)
