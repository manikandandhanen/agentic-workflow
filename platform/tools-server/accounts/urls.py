from rest_framework.routers import DefaultRouter
from django.urls import path, include
from . import viewsets, views

router = DefaultRouter()
router.register(r'tenants', viewsets.TenantViewSet)
router.register(r'teams', viewsets.TeamViewSet)
router.register(r'roles', viewsets.RoleViewSet)
router.register(r'permissions', viewsets.PermissionViewSet)
router.register(r'memberships', viewsets.MembershipViewSet)

urlpatterns = [
    path('', include(router.urls)),
    path('n8n/sso-url/', views.n8n_sso_url, name='n8n-sso-url'),
    path('auth/', include('djoser.urls'), name='djoser-user-urls'),
    path('auth/', include('djoser.urls.jwt'), name='djoser-jwt-urls')
]