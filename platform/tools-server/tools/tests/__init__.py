from __future__ import annotations

"""
Tools tests base helpers.
"""

class ToolsBaseTest:
    def setUp(self):
        # Ensure any parent setUp runs (APITestCase / TestCase)
        try:
            super().setUp()
        except Exception:
            # If super has no setUp or it fails, ignore to keep compatibility as mixin
            pass

    def tearDown(self):
        # Common cleanup for tools tests:
        # - delete uploaded blobs (if storage supports .delete)
        # - remove core models that tests commonly create so tests stay isolated
        # Imports are performed here to avoid import-time side effects.
        try:
            from tools.models import SchemaSource, ApiProvider
            from accounts.models import Tenant, User, Team
        except Exception:
            # If models are not available for some reason, attempt to call super and exit.
            try:
                super().tearDown()
            except Exception:
                pass
            return

        for schema in SchemaSource.objects.all():
            if schema.blob and hasattr(schema.blob, "delete"):
                try:
                    schema.blob.delete(save=False)
                except Exception:
                    pass
        SchemaSource.objects.all().delete()
        ApiProvider.objects.all().delete()
        User.objects.all().delete()
        Team.objects.all().delete()
        Tenant.objects.all().delete()

        try:
            super().tearDown()
        except Exception:
            pass
