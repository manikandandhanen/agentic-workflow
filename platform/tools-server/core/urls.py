"""
URL configuration for core project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.contrib import admin
from django.urls import path, include
from . import views
from django.conf import settings
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularJSONAPIView

urlpatterns = [
    path('core/admin/', admin.site.urls),
    path('core/accounts/', include('accounts.urls')),
    path('core/healthz/', views.healthz),  # health check endpoint
    path('core/tools/', include('tools.urls')),
    path('core/api/v1.0/schema/',
         SpectacularAPIView.as_view(api_version=1.0), name='schema'),
    path('core/api/v1.0/schema/json/',
         SpectacularJSONAPIView.as_view(api_version=1.0), name='schema-json'),
    path(
        'core/api/v1.0/docs/',
        SpectacularSwaggerView.as_view(
            template_name='swagger-ui.html', url_name='schema'
        ),
        name='swagger-ui',
    ),
]

if settings.DEBUG:
    urlpatterns += staticfiles_urlpatterns()