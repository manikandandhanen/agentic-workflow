import hashlib
from django.test import TestCase, override_settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.conf import settings
from unittest.mock import patch
from tools.models import SchemaSource, ApiProvider, SchemaKind
from accounts.models import Tenant, User, Team
from . import ToolsBaseTest

class SchemaSourceBlobUploadTest(ToolsBaseTest, TestCase):
    def setUp(self):
        super().setUp()
        # Create Tenant
        self.tenant = Tenant.objects.create(name="TestTenant", slug="testtenant")
        # Create Team
        self.team = Team.objects.create(tenant=self.tenant, name="TestTeam", slug="test-team")
        # Create User
        self.user = User.objects.create_user(email="user@example.com", password="pass", tenant=self.tenant)
        self.provider = ApiProvider.objects.create(
            tenant=self.tenant,
            name="TestProvider",
            owner_team=self.team,
            base_url="https://api.example.com"
        )
    
    @override_settings(DEFAULT_FILE_STORAGE="django.core.files.storage.InMemoryStorage")
    @patch("tools.models.AzureMediaStorage")
    def test_blob_upload_and_metadata(self, mock_storage):
      
        # Prepare file
        file_content = b"test schema content"
        uploaded_file = SimpleUploadedFile("schema.json", file_content, content_type="application/json")
        # Create SchemaSource with blob
        schema = SchemaSource.objects.create(
            tenant=self.tenant,
            provider=self.provider,
            kind=SchemaKind.OPENAPI,
            blob=uploaded_file,
            created_by=self.user
        )
        # Compute hash and meta
        schema.compute_hash_and_meta()
        # Assertions
        self.assertEqual(schema.content_size, len(file_content))
        self.assertEqual(schema.content_type, "application/json")
        self.assertEqual(schema.sha256, hashlib.sha256(file_content).hexdigest())
        self.assertIsNotNone(schema.blob)
        self.assertTrue(schema.blob.name.startswith(f"schemas/{self.provider.slug}"))

    def tearDown(self):
        # Delete all blobs from Azure storage for SchemaSource instances
        for schema in SchemaSource.objects.all():
            if schema.blob and hasattr(schema.blob, 'delete'):
                try:
                    schema.blob.delete(save=False)
                except Exception:
                    pass  # Ignore errors during cleanup
        SchemaSource.objects.all().delete()
        ApiProvider.objects.all().delete()
        User.objects.all().delete()
        Team.objects.all().delete()
        Tenant.objects.all().delete()
        try:
            super().tearDown()
        except Exception:
            pass
