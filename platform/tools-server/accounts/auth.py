from typing import Optional, Tuple
from django.utils import timezone
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework import exceptions
from django.contrib.auth.models import AnonymousUser

from .models import ServiceToken, Tenant, Team

class ServicePrincipal:
    """
    Lightweight request.user replacement for service tokens.
    Exposes .tenant_id and a fixed role set.
    """
    is_authenticated = True
    is_anonymous = False
    is_superuser = False
    is_staff = False
    is_service_principal = is_service_account = True
    email = "service-token@mcp"

    def __init__(self, identifier: str, tenant: Tenant = None, default_team=Team, scopes: list[str] = [], is_system_management: bool = False):
        self.identifier = identifier # e.g. "<Service token ID>:<service token name>"
        self.tenant = tenant
        self.default_team = default_team
        self.tenant_id = tenant.id if tenant else None
        self.scopes = scopes
        self.is_system_management = is_system_management
        if is_system_management:
            self.is_staff = True


class BearerServiceTokenAuthentication(BaseAuthentication):
    keyword = "Bearer"

    def authenticate(self, request) -> Optional[Tuple[ServicePrincipal, None]]:
        auth = get_authorization_header(request).split()
        # print("BearerServiceTokenAuthentication AUTH HEADER:", auth)
        if not auth or auth[0].lower() != self.keyword.lower().encode():
            return None
        if len(auth) == 1:
            raise exceptions.AuthenticationFailed("Invalid Authorization header. No credentials provided.")
        token = auth[1].decode("utf-8")

        sha = ServiceToken.hash_token(token)
        try:
            st = ServiceToken.objects.select_related("tenant").get(sha256=sha, is_active=True)
        except ServiceToken.DoesNotExist:
            return None # allow other authentication classes to try

        if st.expires_at and st.expires_at < timezone.now():
            raise exceptions.AuthenticationFailed("Service token expired")

        # mark last used (lightweight)
        ServiceToken.objects.filter(pk=st.pk).update(last_used_at=timezone.now())

        principal_identifier = f"{st.id}:{st.name}"
        principal = ServicePrincipal(principal_identifier, tenant=st.tenant, default_team=st.owner_team, scopes=st.scopes, is_system_management=st.is_system_management)
        # print('BearerServiceTokenAuthentication -> principal:', principal.__dict__)
        return principal, None
