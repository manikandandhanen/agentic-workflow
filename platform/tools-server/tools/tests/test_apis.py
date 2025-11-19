import io
import json

from django.urls import reverse
from rest_framework.test import APITestCase

from accounts.models import Tenant, Team, User, Role, Membership
from tools.models import AccessGrant, NormalizedCapability, SchemaKind
from pprint import pprint
from . import ToolsBaseTest

class NormalizeFlowAPITest(ToolsBaseTest, APITestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(name="Globex", slug="globex")
        self.team = Team.objects.create(tenant=self.tenant, name="Ops", slug="ops")
        self.user = User.objects.create_user(email="u@globex.io", password="x", tenant=self.tenant)
        self.role = Role.objects.create(tenant=self.tenant, name="Engineer", slug="engineer")
        self.membership = Membership.objects.create(user=self.user, team=self.team)
        self.membership.roles.set([self.role])
        self.user.default_team = self.team
        self.user.save() 
        self.client.force_authenticate(user=self.user)

        self.oas_sample = {
            "openapi": "3.0.1",
            "paths": {
                "/accounts": {
                    "post": {
                        "operationId": "CreateAccount",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}
                                }
                            },
                        },
                        "responses": {"201": {"content": {"application/json": {"schema": {"type": "object"}}}}}
                    }
                }
            }
        }

        # Provider
        resp = self.client.post(
            reverse("tools:tools-providers-list"),
            {
                "name": "crm",
                "owner_team": str(self.team.id),
                "base_url": "https://crm.globex.com",
                "auth_profile": "none",
                "status": "draft",
                "domain_allowlist": ["crm.globex.com"],
            },
            format="json",
        )
        self.assertEqual(resp.status_code, 201, resp.content)
        self.provider_id = resp.data["id"]

    def _upload_sample_schema(self) -> str:
        buf = io.BytesIO(json.dumps(self.oas_sample).encode("utf-8"))
        buf.name = "openapi.json"
        sresp = self.client.post(
            reverse("tools:tools-schemas-list"),
            {"provider": self.provider_id, "kind": SchemaKind.OPENAPI, "blob": buf},
            format="multipart",
        )
        self.assertEqual(sresp.status_code, 201, sresp.content)
        return sresp.data["schema"]["id"]

    def _normalize_schema(self, schema_id: str):
        norm_url = reverse("tools:tools-schemas-normalize", kwargs={"pk": schema_id})
        return self.client.post(norm_url, {}, format="json")

    # def _enable_and_grant(self, version: int):
    #     cap = NormalizedCapability.objects.filter(provider_id=self.provider_id, version=version).first()
    #     self.assertIsNotNone(cap, "Expected a normalized capability to exist")
    #     cap.enabled = True
    #     cap.save()
    #     AccessGrant.objects.create(team=self.team, capability=cap, version=version, scopes=[], approved_by=self.user)
    #     return cap

    def test_normalize_basic(self):
        schema_id = self._upload_sample_schema()                    # version 1
        nresp = self._normalize_schema(schema_id)                   # version 2
        self.assertEqual(nresp.status_code, 201, nresp.content)
        self.assertEqual(nresp.data["count_created"], 1)
        self.assertEqual(nresp.data["version"], 2)
        self.assertTrue(nresp.data["openapi_version"].startswith("3."))

        sample = nresp.data["sample"][0]
        self.assertEqual(
            sample["json_schema_in"],
            {
                "type": "object",
                "properties": {
                    "body": {
                        "type": "object",
                        "properties": {"name": {"type": "string"}},
                        "required": ["name"],
                    }
                },
                "required": ["body"],
                "additionalProperties": False,
            },
        )
        self.assertEqual(sample["json_schema_out"], {"type": "object"})
        self.assertEqual(sample["name"], "globex:crm.account.create")

    def test_capabilities_listing(self):
        schema_id = self._upload_sample_schema()
        nresp = self._normalize_schema(schema_id)
        self.assertEqual(nresp.status_code, 201, nresp.content)
        # version = nresp.data["version"]
        # # self._enable_and_grant(version)

        cap_url = f"{reverse('tools:tools-capabilities-list')}?tenant={self.tenant.slug}&team={self.team.slug}&active=true"
        cresp = self.client.get(cap_url, {}, format="json")
        print("capabilities response:>>>>>>>>>> ")
        pprint(cresp.data)
        self.assertEqual(cresp.status_code, 200, cresp.content)
        self.assertIn("cap_set_id", cresp.data)
        self.assertIn("etag", cresp.data)
        self.assertEqual(len(cresp.data["capabilities"]), 1)
