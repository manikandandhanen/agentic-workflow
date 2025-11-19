"""
Development Django settings.
"""
from .base import *
from decouple import Config, RepositoryEnv

config = Config(RepositoryEnv('.env.dev'))

DEBUG = True
ALLOWED_HOSTS = ["*"]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'miqdb',
        'USER': 'miq',
        'PASSWORD': 'miqpassword',
        'HOST': 'dev_db',
        'PORT': '5432',
    }
}

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": config("REDIS_URL", default="redis://dev_redis:6379/1"),
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            "COMPRESSOR": "django_redis.compressors.zlib.ZlibCompressor",
        },
        "TIMEOUT": 300,
    }
}

# Azure Storage Settings
AZURE_ACCOUNT_NAME = config("AZURE_ACCOUNT_NAME")
AZURE_ACCOUNT_KEY = config("AZURE_ACCOUNT_KEY")
AZURE_CONTAINER_NAME = config("AZURE_CONTAINER_NAME", default="miqhub-media")