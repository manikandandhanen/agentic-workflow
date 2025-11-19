# accounts/admin.py
from django.contrib import admin
from .models import Tenant, Team, Role, Permission, Membership, User

class MembershipInline(admin.TabularInline):
    model = Membership
    extra = 0
    filter_horizontal = ("roles",)

@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    list_display = ("id", "name", "slug", "created_at")
    search_fields = ("name", "slug")

@admin.register(Team)
class TeamAdmin(admin.ModelAdmin):
    list_display = ("id", "tenant", "name", "slug")
    list_filter = ("tenant",)
    search_fields = ("name", "slug")

@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ("id", "tenant", "name")
    list_filter = ("tenant",)
    search_fields = ("name",)
    filter_horizontal = ("permissions",)

@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    list_display = ("id", "resource", "action")
    list_filter = ("resource", "action")
    search_fields = ("resource",)

@admin.register(Membership)
class MembershipAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "team", "created_at")
    list_filter = ("team__tenant", "team")
    filter_horizontal = ("roles",)

# @admin.register(Tool)
# class ToolAdmin(admin.ModelAdmin):
#     list_display = ("id", "provider", "name", "scope", "tenant", "created_at")
#     list_filter = ("scope", "tenant", "provider")
#     search_fields = ("provider", "name")
#     filter_horizontal = ("teams",)

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ("id", "email", "tenant", "default_team", "is_active", "is_staff", "is_superuser")
    search_fields = ("email",)
    list_filter = ("tenant", "is_active", "is_staff", "is_superuser")
    inlines = [MembershipInline]
    fieldsets = (
        (None, {"fields": ("email", "password", "tenant", "default_team", "display_name", "is_service_account")}),
        ("Permissions", {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}),
        ("Important dates", {"fields": ("last_login", "date_joined")}),
    )
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": ("email", "tenant", "default_team", "password1", "password2", "is_active", "is_staff", "is_superuser"),
        }),
    )
