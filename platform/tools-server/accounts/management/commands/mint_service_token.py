from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from accounts.models import Tenant, ServiceToken

class Command(BaseCommand):
    '''
    Django management command to create a new service token for a specified tenant.
    Example usage:
        python manage.py mint_service_token --tenant=my-tenant --team=some-team --name="My Service Token" --scopes="capabilities:read" --created-by="email@example.com"    
    '''
    help = "Create a new service token and print the plaintext token once."

    def add_arguments(self, parser):
        parser.add_argument("--tenant", required=True, help="Tenant Slug")
        parser.add_argument("--name", required=True, help="Service Token Name")
        parser.add_argument("--team", required=True, help="Team Slug")
        parser.add_argument("--scopes", nargs="+", default=["capabilities:read"])
        parser.add_argument("--created-by", required=True, help="MIQ Core Admin Email")
        parser.add_argument("--days", type=int, default=365)

    def handle(self, *args, **opts):
        User = get_user_model()
        try:
            tenant = Tenant.objects.get(name__iexact=opts["tenant"])
        except Tenant.DoesNotExist:
            self.stdout.write(self.style.HTTP_INFO("Tenant not found by name, trying slug..."))
            tenant = Tenant.objects.get(slug__iexact=opts["tenant"])
        try:
            team = tenant.teams.get(slug__iexact=opts["team"])
        except Tenant.teams.RelatedObjectDoesNotExist:
            self.stdout.write(self.style.ERROR(f"Team '{opts['team']}' not found in tenant '{tenant.name}'"))
            return
        created_by = User.objects.get(email=opts["created_by"])
        token = ServiceToken.mint_plaintext()
        sha = ServiceToken.hash_token(token)

        from django.utils import timezone
        expires_at = timezone.now() + timezone.timedelta(days=opts["days"])

        _ = ServiceToken.objects.create(
            tenant=tenant,
            owner_team=team,
            name=opts["name"],
            sha256=sha,
            scopes=opts["scopes"],
            created_by=created_by,
            expires_at=expires_at,
            is_active=True,
        )
        self.stdout.write(self.style.SUCCESS("Service token created. SAVE THIS NOW:"))
        self.stdout.write(token)
