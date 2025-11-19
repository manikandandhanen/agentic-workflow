from decouple import config
from django.core.management import BaseCommand, call_command
from accounts.fixtures import seed_permissions, seed_miq_core_admin_account

class Command(BaseCommand):
    help = "Loads initial dependencies."

    def handle(self, *args, **kwargs):
        seed_permissions.seed()
        self.stdout.write(self.style.SUCCESS('Successfully seeded permissions.'))

        tenant, team = seed_miq_core_admin_account.seed()
        self.stdout.write(self.style.SUCCESS('Successfully seeded MIQ Core admin account.'))

        service_token_name = f"service-token:{tenant.slug}:{team.slug}"
        created_by_email = config("DEFAULT_ADMIN_USER_EMAIL", default="miq_admin@mastec.com")
        call_command(
            "mint_service_token",
            tenant=tenant.slug,
            name=service_token_name,
            scopes=["capabilities:read"],
            created_by=created_by_email,
        )
        self.stdout.write(self.style.SUCCESS(f'Successfully minted MIQ Core service token "{service_token_name}".'))
