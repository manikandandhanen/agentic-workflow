from djoser.serializers import TokenCreateSerializer as BaseTokenCreateSerializer
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer as BaseTokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.models import TokenUser as BaseTokenUser

from .models import Membership

import jwt
from datetime import datetime, timedelta
from django.conf import settings

def _enrich_refresh_with_claims(refresh: RefreshToken, user) -> RefreshToken:
    """
    Populate tenant/team/role/service-account information on the refresh token.
    Access tokens minted from this refresh inherit the same claims.
    """
    refresh["email"] = user.email
    refresh["tenant"] = {
        "id": str(user.tenant_id) if user.tenant_id else None,
        "slug": getattr(user.tenant, "slug", None),
    }
    refresh["svc"] = bool(user.is_service_account)

    memberships = (
        Membership.objects
        .filter(user=user)
        .select_related("team__tenant")
        .prefetch_related("roles")
    )

    refresh["teams"] = [{"id": str(m.team_id), "slug": m.team.slug} for m in memberships]
    refresh["roles"] = sorted({r.slug for m in memberships for r in m.roles.all()})
    return refresh


class TokenCreateSerializer(BaseTokenCreateSerializer):
    """
    On successful login, include tenant, teams, and roles in the access token.
    Keep claims lean to avoid oversize tokens.
    """
    def validate(self, attrs):
        data = super().validate(attrs)
        user = self.user

        refresh = _enrich_refresh_with_claims(RefreshToken.for_user(user), user)

        data["access"] = str(refresh.access_token)
        data["refresh"] = str(refresh)
        return data


class TokenObtainPairSerializer(BaseTokenObtainPairSerializer):
    """
    Mirror the claim enrichment when hitting SimpleJWT's default obtain pair view.
    """
    def validate(self, attrs):
        data = super().validate(attrs)
        user = self.user

        refresh = _enrich_refresh_with_claims(RefreshToken(data["refresh"]), user)
        data["refresh"] = str(refresh)
        data["access"] = str(refresh.access_token)
        return data


class TokenUser(BaseTokenUser):
    """
    Enhances TokenUser to expose tenant/teams/roles from claims (read-only).
    """
    @property
    def email(self):
        return self.token.payload.get("email")

    @property
    def tenant(self):
        return self.token.payload.get("tenant")

    @property
    def teams(self):
        return self.token.payload.get("teams", [])

    @property
    def roles(self):
        return self.token.payload.get("roles", [])

    @property
    def is_service_account(self):
        return bool(self.token.payload.get("svc", False))
    
def create_n8n_sso_token(user, expires_in_minutes: int = 5) -> str:
    payload = {
        "sub": str(user.id),
        "email": user.email,
        "first_name": user.first_name or "",
        "last_name": user.last_name or "",
        "tenant": {
            "id": str(user.tenant_id) if user.tenant_id else None,
            "slug": getattr(user.tenant, "slug", None),
        },
        "svc": bool(user.is_service_account),
        "iss": "mi-qhub",
        "aud": "n8n",
        "exp": datetime.utcnow() + timedelta(minutes=expires_in_minutes),
    }

    secret = getattr(settings, "N8N_SSO_SECRET", None)
    if not secret:
        raise RuntimeError("N8N_SSO_SECRET is not configured in Django settings")

    return jwt.encode(payload, secret, algorithm="HS256")