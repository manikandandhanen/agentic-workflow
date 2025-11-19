from django.urls import path, include
from rest_framework.routers import DefaultRouter
from tools.viewsets import ApiProviderViewSet, SchemaSourceViewSet, CapabilitiesViewSet
from tools import views

app_name = "tools"

router = DefaultRouter()
API_VERSION = "v1.0"
API_PREFIX = f"api/{API_VERSION}"

router.register(r"providers", ApiProviderViewSet, basename="tools-providers")
router.register(r"schemas", SchemaSourceViewSet, basename="tools-schemas")
router.register(r"capabilities", CapabilitiesViewSet, basename="tools-capabilities")

urlpatterns = [
    path(f"{API_PREFIX}/", include(router.urls)),
    path("home/", views.home, name="tools-home"),
    path("mcp-tools/", views.ListMCPTools.as_view(), name="mcp-tools-list"),
]

# PROVIDERS_API_VERSION = "v1.0"
# PROVIDERS_API_SUFFIX = f"api/{PROVIDERS_API_VERSION}/"

# SCHEMAS_API_VERSION = "v1.0"
# SCHEMAS_API_SUFFIX = f"api/{SCHEMAS_API_VERSION}/"

# CAPABILITIES_API_VERSION = "v1.0"
# CAPABILITIES_API_SUFFIX = f"api/{CAPABILITIES_API_VERSION}/"

# router.register(rf"providers/{PROVIDERS_API_SUFFIX}", ApiProviderViewSet, basename="tools-providers")
# router.register(rf"schemas/{SCHEMAS_API_SUFFIX}", SchemaSourceViewSet, basename="tools-schemas")
# router.register(rf"capabilities/{CAPABILITIES_API_SUFFIX}", CapabilitiesViewSet, basename="tools-capabilities")
