from decouple import config
from django.utils.text import slugify
from django.contrib.auth import get_user_model

User = get_user_model()

def seed() -> tuple:
    from accounts.models import Tenant, Team
    DEFAULT_TENANT = config("MCP_TENANT_NAME", default="miq-core-tenant")
    DEFAULT_TEAM   = config("MCP_TEAM_NAME", default="miq-core-team")
    DEFAULT_ADMIN_USER_EMAIL = config("DEFAULT_ADMIN_USER_EMAIL", default="miq_admin@mastec.com")

    User.objects.get_or_create(email=DEFAULT_ADMIN_USER_EMAIL)
    tenant, _ = Tenant.objects.get_or_create(name="MIQ Core Tenant", slug=slugify(DEFAULT_TENANT))
    team, _ = Team.objects.get_or_create(
        tenant=tenant, 
        name="MIQ Core Team", 
        slug=slugify(DEFAULT_TEAM))
    return tenant, team
    