"""
Base Django settings for all environments.
"""

from pathlib import Path
from datetime import timedelta
import os
from decouple import config 


N8N_SSO_SECRET = os.getenv("N8N_SSO_SECRET", "dev-n8n-sso-secret")
N8N_EMBED_URL = os.getenv("N8N_EMBED_URL", "http://localhost:8090/")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
CORE_DIR = BASE_DIR / "core"

SECRET_KEY = os.getenv(
    "DJANGO_SECRET_KEY",
    "django-insecure-3e2fw=8a^h@b1s%ajmr=imh31y_@hzo$*8+q*@8-xj-vxsliw!",
)

DEBUG = False

ALLOWED_HOSTS = []

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.postgres",  # for ArrayField
    "corsheaders",
    "rest_framework",
    "djoser",
    "rest_framework_simplejwt",
    "drf_spectacular",
    "django_redis",
    "accounts",
    "tools",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    # cors headers
    "corsheaders.middleware.CorsMiddleware",
    # -
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "core.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [CORE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "core.wsgi.application"

AUTH_USER_MODEL = "accounts.User"

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "static"
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "accounts.auth.BearerServiceTokenAuthentication",
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}

CORS_ALLOWED_ORIGINS = [
    "http://localhost:8088",
    "http://localhost:5173",
    "http://127.0.0.1:8005",
    "http://127.0.0.1:8081",
    "http://127.0.0.1:4200",
    "http://localhost:4200",
    r"^http://localhost:\d+$",
    "http://localhost:5678",
    "http://localhost:8089",
    "http://localhost:5678"
]

SIMPLE_JWT = {
    "AUTH_HEADER_TYPES": ("Bearer", "JWT"),  # for service tokens  # for user tokens
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=60),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "TOKEN_USER_CLASS": "accounts.jwt.TokenUser",
    "SIGNING_KEY": SECRET_KEY,
    "ALGORITHM": "HS256",
    "TOKEN_OBTAIN_SERIALIZER": "accounts.jwt.TokenObtainPairSerializer",
}

DJOSER = {
    "LOGIN_FIELD": "email",
    "USER_ID_FIELD": "id",
    "SERIALIZERS": {
        "token_create": "accounts.jwt.TokenCreateSerializer",
    },
    "AUTHENTICATION_BACKENDS": (
        "accounts.auth.BearerServiceTokenAuthentication",
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
}

SPECTACULAR_SETTINGS = {
    "TITLE": "BOT MANAGER API",
    "DESCRIPTION": "Bot Manager API documentation",
    "VERSION": "1.0.1",
    "SERVE_INCLUDE_SCHEMA": False,
    "SCHEMA_PATH_PREFIX": "/core/",
    "SWAGGER_UI_SETTINGS": {
        "persistAuthorization": True,
    },
}

# SPECTACULAR_SETTINGS = {
#     'TITLE': 'Your API Title',
#     'DESCRIPTION': 'Your API description',
#     'VERSION': '1.0.0',
#     'SERVE_INCLUDE_SCHEMA': False,
#     'COMPONENT_SPLIT_REQUEST': True,
#     'APPEND_COMPONENTS': {},
#     'PREPROCESSING_HOOKS': [],
#     'POSTPROCESSING_HOOKS': [],
#     'SCHEMA_PATH_PREFIX_TRIM': True,
#     # 'SCHEMA_PATH_PREFIX': '/api/v1/',
#     'SERVE_PERMISSIONS': ['rest_framework.permissions.AllowAny'],
#     'SERVE_AUTHENTICATION': [],
#     'ENABLE_DJOSER': True,  # Optional, for clarity
# }
