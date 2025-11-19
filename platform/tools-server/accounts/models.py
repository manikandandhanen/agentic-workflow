import secrets, hashlib
from django.conf import settings
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractUser
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.functions import Lower
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from uuid import uuid4


# -------------------------
# Mixins
# -------------------------
class TimeStampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class UUIDModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False, serialize=False, verbose_name="ID")

    class Meta:
        abstract = True

# -------------------------
# Tenancy
# -------------------------
class Tenant(TimeStampedModel, UUIDModel):
    name = models.CharField(max_length=200, unique=True)
    slug = models.SlugField(max_length=200, unique=True, db_index=True)

    class Meta:
        ordering = ("slug",)

    def __str__(self):
        return self.name


class Team(TimeStampedModel):
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="teams")
    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=200)

    class Meta:
        unique_together = (("tenant", "slug"), ("tenant", "name"))
        indexes = [
            models.Index(fields=("tenant", "slug")),
            models.Index(fields=("tenant", "name")),
        ]
        ordering = ("tenant__slug", "slug")

    def __str__(self):
        return f"{self.tenant.slug}:{self.slug}"


# -------------------------
# Permissions & Roles
# -------------------------
class PermissionAction(models.TextChoices):
    CREATE   = "create",  _("Create")
    RETRIEVE = "retrieve",_("Retrieve/View")
    UPDATE   = "update",  _("Update")
    DELETE   = "delete",  _("Delete")
    EXECUTE  = "execute", _("Execute/Run")


class Permission(TimeStampedModel):
    """
    Low-level, composable permission/action, optionally namespaced to a resource.
    e.g., resource="tool", action="execute" or resource="schema", action="update"
    """
    resource = models.CharField(max_length=100)  # e.g., "tool", "capability", "schema"
    action = models.CharField(max_length=16, choices=PermissionAction.choices)

    class Meta:
        unique_together = (("resource", "action"),)
        ordering = ("resource", "action")
        indexes = [models.Index(fields=("resource", "action"))]

    def __str__(self):
        return f"{self.resource}:{self.action}"


class Role(TimeStampedModel):
    """
    Role = named bundle of permissions. Roles are attached to team memberships.
    """
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="roles")
    name = models.CharField(max_length=120)  # e.g., "admin", "approver", "reader"
    slug = models.SlugField(max_length=120, help_text=_("Stable identifier for policy files / IaC."), db_index=True)
    description = models.TextField(blank=True)
    permissions = models.ManyToManyField(Permission, related_name="roles", blank=True)

    class Meta:
        unique_together = (("tenant", "name"), ("tenant", "slug"))
        ordering = ("tenant__slug", "slug")

    def __str__(self):
        return f"{self.tenant.slug}:{self.name}"


# -------------------------
# User model (email-as-username) + Service accounts
# -------------------------
class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError("The Email must be set")
        email = self.normalize_email(email)
        extra_fields.setdefault("is_active", True)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.full_clean(exclude=["password"])  # model-level validation
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")
        return self._create_user(email, password, **extra_fields)


class User(AbstractUser):
    """
    Custom user:
    - Email is the unique login field (with case-insensitive uniqueness).
    - Users belong primarily to a tenant, and can join multiple teams under that tenant.
    - 'is_service_account' distinguishes machine principals (for bots/gateways).
    """
    username = None  # remove username field from AbstractUser
    email = models.EmailField(unique=True)
    display_name = models.CharField(max_length=150, blank=True)
    tenant = models.ForeignKey(
        Tenant, on_delete=models.PROTECT, related_name="users", null=True, blank=True
    )
    is_service_account = models.BooleanField(default=False)
    default_team = models.ForeignKey(
        'Team', on_delete=models.SET_NULL, null=True, blank=True, related_name='default_users',
        help_text=_('Default team for resource ownership. Must be a team the user is a member of.')
    )

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = UserManager()

    class Meta:
        constraints = [
            # Enforce case-insensitive uniqueness for email
            models.UniqueConstraint(Lower("email"), name="accounts_user_email_ci_unique"),
        ]
        ordering = ("email",)

    def __str__(self):
        return self.email

    def clean(self):
        super().clean()
        # If default_team is set, ensure user is a member and team is in same tenant
        if self.default_team:
            if self.tenant and self.default_team.tenant_id != self.tenant_id:
                raise ValidationError({
                    'default_team': _('Default team must belong to the same tenant as the user.')
                })
            if not self.memberships.filter(team=self.default_team).exists():
                raise ValidationError({
                    'default_team': _('User must be a member of the default team.')
                })

    # Convenience: compute effective permissions for a given team
    def effective_permissions(self, team: "Team") -> set[tuple[str, str]]:
        """
        Returns a set of (resource, action) tuples the user has within `team`.
        """
        perms = (
            Permission.objects
            .filter(roles__memberships__user=self, roles__memberships__team=team)
            .values_list("resource", "action")
            .distinct()
        )
        return set(perms)

    def is_part_of_tenant(self, tenant: Tenant) -> bool:
        if self.tenant_id == tenant.id:
            return True
        return self.memberships.filter(team__tenant=tenant).exists()
    
    def is_part_of_team(self, team: Team) -> bool:
        return self.memberships.filter(team=team).exists()

    @property
    def is_service_principal(self) -> bool:
        return self.is_service_account


class ServiceToken(models.Model):
    """
    Personal Access Token for service-to-service auth.
    Only the SHA-256 hash is stored. Plain token is shown once on creation.
    """
    id = models.BigAutoField(primary_key=True)
    tenant = models.ForeignKey("accounts.Tenant", on_delete=models.CASCADE, related_name="service_tokens")
    owner_team = models.ForeignKey(Team, on_delete=models.PROTECT, related_name="owned_service_tokens", null=True, blank=True)
    sponsor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="sponsored_service_tokens", null=True, blank=True)
    name = models.CharField(max_length=120)  # e.g., "mcp-registry"
    sha256 = models.CharField(max_length=64, unique=True, db_index=True)
    scopes = models.JSONField(default=list)  # e.g., ["capabilities:read"]
    is_active = models.BooleanField(default=True)
    is_system_management = models.BooleanField(default=False, help_text=_("Used for system management tasks and communication."))
    
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="created_service_tokens")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = (("tenant", "name"),)

    def mark_used(self):
        self.last_used_at = timezone.now()
        self.save(update_fields=["last_used_at"])

    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def mint_plaintext() -> str:
        # 40 chars ~ 200 bits
        return secrets.token_urlsafe(30)


# -------------------------
# Membership (per-team roles)
# -------------------------
class Membership(TimeStampedModel):
    """
    User can be part of multiple teams (typically in the same tenant).
    Each membership may carry multiple roles (fine-grained RBAC per team).
    """
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="memberships")
    team = models.ForeignKey(Team, on_delete=models.CASCADE, related_name="memberships")
    roles = models.ManyToManyField(Role, related_name="memberships", blank=True)

    class Meta:
        unique_together = (("user", "team"),)
        indexes = [
            models.Index(fields=("user", "team")),
        ]
        ordering = ("team__tenant__slug", "team__slug", "user__email")

    def __str__(self):
        return f"{self.user.email} ∈ {self.team}"

    # Guard against cross-tenant membership (keeps RBAC/Secrets sane)
    def clean(self):
        super().clean()
        if self.user.tenant_id and self.team.tenant_id and self.user.tenant_id != self.team.tenant_id:
            raise ValidationError(_("User tenant and team tenant must match."))

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)


# -------------------------
# Visibility & Tool registry (for MCP exposure)
# -------------------------
class VisibilityScope(models.TextChoices):
    TEAM   = "team",   _("Team")
    TENANT = "tenant", _("Tenant")
    GLOBAL = "global", _("Global")
