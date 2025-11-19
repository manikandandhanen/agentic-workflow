from copy import deepcopy

from django.conf import settings
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import AccessToken

from accounts.jwt import TokenUser
from accounts.models import Membership, Role, Team, Tenant, User


class JWTAuthenticationTests(APITestCase):
    password = "StrongPass!1"

    def setUp(self):
        self.tenant = Tenant.objects.create(name="Tenant A", slug="tenant-a")
        self.team = Team.objects.create(tenant=self.tenant, name="Team A", slug="team-a")
        self.role = Role.objects.create(tenant=self.tenant, name="Admin", slug="admin")
        self.user = User.objects.create_user(
            email="user@example.com",
            password=self.password,
            tenant=self.tenant,
        )
        membership = Membership.objects.create(user=self.user, team=self.team)
        membership.roles.add(self.role)
        self.token_url = reverse("jwt-create")

    def _obtain_tokens(self):
        response = self.client.post(
            self.token_url,
            {"email": self.user.email, "password": self.password},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("access", response.data)
        self.assertIn("refresh", response.data)
        return response.data

    def test_jwt_token_contains_tenant_team_and_role_claims(self):
        tokens = self._obtain_tokens()
        access = AccessToken(tokens["access"])
        
        tenant_claim = access.payload.get("tenant")
        self.assertIsInstance(tenant_claim, dict)
        self.assertEqual(tenant_claim["slug"], self.tenant.slug)
        self.assertEqual(str(tenant_claim["id"]), str(self.tenant.id))

        self.assertEqual(access.payload.get("roles"), ["admin"])
        self.assertEqual(access.payload.get("teams"), [{"id": str(self.team.id), "slug": self.team.slug}])
        self.assertFalse(access.payload.get("svc"))
        self.assertEqual(int(access.payload.get("user_id")), self.user.id)

    def test_jwt_authenticated_request_is_allowed(self):
        tokens = self._obtain_tokens()
        access = tokens["access"]

        jwt_only_rf = deepcopy(settings.REST_FRAMEWORK)
        jwt_only_rf["DEFAULT_AUTHENTICATION_CLASSES"] = (
            "rest_framework_simplejwt.authentication.JWTAuthentication",
        )

        with override_settings(REST_FRAMEWORK=jwt_only_rf):
            self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
            response = self.client.get(reverse("tenant-list"))

        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(len(response.data), 1)

    def test_token_user_exposes_claims_from_access_token(self):
        tokens = self._obtain_tokens()
        access_token = AccessToken(tokens["access"])

        token_user = TokenUser(access_token)

        self.assertEqual(int(token_user.id), self.user.id)
        self.assertEqual(token_user.email, self.user.email)
        self.assertEqual(token_user.tenant["slug"], self.tenant.slug)
        self.assertFalse(token_user.is_service_account)
        self.assertEqual(token_user.teams, [{"id": str(self.team.id), "slug": self.team.slug}])
        self.assertEqual(token_user.roles, ["admin"])
