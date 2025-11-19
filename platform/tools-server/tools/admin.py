from django.contrib import admin
from .models import ApiProvider, SchemaSource, NormalizedCapability, AccessGrant, ExecutionLog

@admin.register(ApiProvider)
class ApiProviderAdmin(admin.ModelAdmin):
    list_display = ("name", "tenant", "owner_team", "status", "auth_profile")
    search_fields = ("name", "base_url")
    list_filter = ("status", "auth_profile", "tenant")

@admin.register(SchemaSource)
class SchemaSourceAdmin(admin.ModelAdmin):
    list_display = ("id", "tenant", "provider", "kind", "url", "etag", "content_type", "content_size", "created_at")
    list_filter = ("kind", "tenant", "provider")

@admin.register(NormalizedCapability)
class NormalizedCapabilityAdmin(admin.ModelAdmin):
    list_display = ("name", "provider", "version", "enabled", "risk_level")
    list_filter = ("enabled", "risk_level", "provider")

@admin.register(AccessGrant)
class AccessGrantAdmin(admin.ModelAdmin):
    list_display = ("team", "capability", "version", "expires_at")
    list_filter = ("team",)

@admin.register(ExecutionLog)
class ExecutionLogAdmin(admin.ModelAdmin):
    list_display = ("tenant", "capability", "version", "status", "latency_ms", "timestamp")
    list_filter = ("status", "tenant")
