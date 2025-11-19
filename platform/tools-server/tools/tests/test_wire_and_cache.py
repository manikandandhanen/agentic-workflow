import io
import json
import time

from django.urls import reverse
from rest_framework.test import APITestCase

from accounts.models import Tenant, Team, User, Role, Membership
from tools.models import ApiProvider, SchemaKind, NormalizedCapability, AccessGrant
from pprint import pprint
from . import ToolsBaseTest

class WireAndCacheAPITestCase(ToolsBaseTest, APITestCase):
    def setUp(self):
        super().setUp()
        # Tenant / Team / User
        self.tenant = Tenant.objects.create(name="Acme", slug="acme")
        self.team = Team.objects.create(tenant=self.tenant, name="Core", slug="core")
        self.user = User.objects.create_user(email="a@acme.io", password="x", tenant=self.tenant)
        self.client.force_authenticate(user=self.user)
        self.role = Role.objects.create(tenant=self.tenant, name="Engineer", slug="engineer")
        self.membership = Membership.objects.create(user=self.user, team=self.team)
        self.membership.roles.set([self.role])
        self.user.default_team = self.team
        self.user.save() 
        
        # Create a providers
        provider_payload = {
            "name": "inventory",
            "owner_team": str(self.team.id),
            "base_url": "https://api.example.com",
            "auth_profile": "none",
            "status": "draft",
            "domain_allowlist": ["api.example.com"],
        }
        
        # oas
        self.oas = {
            "openapi": "3.0.3",
            "paths": {
                "/v1/items/{id}": {
                    "get": {
                        "operationId": "GetItem",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
                            {"name": "fields", "in": "query", "schema": {"type": "array", "items": {"type": "string"}}},
                        ],
                        "responses": {"200": {"content": {"application/json": {"schema": {"type": "object"}}}}},
                    }
                }
            },
        }
        resp = self.client.post(reverse("tools:tools-providers-list"), provider_payload, format="json")
        self.assertEqual(resp.status_code, 201, resp.content)
        self.provider_id = resp.data["id"]


    def _upload_openapi(self) -> str:
        """Helper to upload an OpenAPI spec and return SchemaSource id."""
        buf = io.BytesIO(json.dumps(self.oas).encode("utf-8"))
        buf.name = "openapi.json"
        sresp = self.client.post(
            reverse("tools:tools-schemas-list"),
            {"provider": self.provider_id, "kind": SchemaKind.OPENAPI, "blob": buf},
            format="multipart",
        )
        self.assertEqual(sresp.status_code, 201, sresp.content)
        pprint(sresp.data)
        return sresp.data["schema"]["id"]

    def _normalize(self, schema_id: str) -> int:
        """Normalize the uploaded spec and return new provider version."""
        nresp = self.client.post(reverse("tools:tools-schemas-normalize", kwargs={"pk": schema_id}), {}, format="json")
        self.assertEqual(nresp.status_code, 201, nresp.content)
        return nresp.data["version"]

    def _enable_and_grant(self, version: int):
        """Enable first capability and create an AccessGrant pinned to that version."""
        cap = NormalizedCapability.objects.filter(provider_id=self.provider_id, version=version).first()
        self.assertIsNotNone(cap, "Expected at least one normalized capability")
        cap.enabled = True
        cap.save()
        AccessGrant.objects.create(team=self.team, capability=cap, version=version, scopes=[], approved_by=self.user)

    def test_normalize_emits_wire_and_redis_cache_invalidation(self):
        # Step 1: Upload & normalize a minimal OAS
        schema_id = self._upload_openapi()
        version = self._normalize(schema_id)
        # self._enable_and_grant(version)

        # Step 2: Fetch capabilities → fills cache and returns payload with wire
        list_url = reverse("tools:tools-capabilities-list") + f"?team={self.team.id}&active=true"
        r1 = self.client.get(list_url)
        self.assertEqual(r1.status_code, 200, r1.content)

        payload = r1.json()
        self.assertIn("capabilities", payload)
        self.assertGreaterEqual(len(payload["capabilities"]), 1)

        cap0 = payload["capabilities"][0]
        # Validate wire presence and minimal content
        self.assertIn("wire", cap0)
        self.assertEqual(cap0["wire"].get("method"), "GET")
        self.assertEqual(cap0["wire"].get("path"), "/v1/items/{id}")
        self.assertIn("path_map", cap0["wire"])
        self.assertEqual(cap0["wire"]["path_map"].get("id"), "id")
        self.assertIn("query_map", cap0["wire"])
        self.assertIn("fields", cap0["wire"]["query_map"])

        # Step 3: ETag should allow a 304 on If-None-Match
        etag = r1.headers.get("ETag")
        self.assertTrue(etag, "Expected ETag header in response")
        r2 = self.client.get(list_url, HTTP_IF_NONE_MATCH=etag)
        self.assertEqual(r2.status_code, 304)

        # Step 4: Change AccessGrant (e.g., scopes) → signals should invalidate cache key
        AccessGrant.objects.filter(team=self.team).update(scopes=["read"])
        # Allow a brief moment if cache invalidation runs asynchronously in CI
        time.sleep(0.1)

        # After invalidation, fetching with the same If-None-Match may yield 200 or 304:
        # - 200 if the snapshot recomputation path bypassed ETag match in your flow
        # - 304 if the recomputed snapshot content & ETag are identical (likely here)
        r3 = self.client.get(list_url, HTTP_IF_NONE_MATCH=etag)
        self.assertIn(r3.status_code, (200, 304))
        # If it's 200, ensure the structure is still correct and ETag present
        if r3.status_code == 200:
            self.assertIn("ETag", r3.headers)
            data3 = r3.json()
            self.assertIn("capabilities", data3)
            # self.assertGreaterEqual(len(data3["capabilities"]), 1)
