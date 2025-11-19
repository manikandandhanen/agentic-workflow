from __future__ import annotations
import json
from django.core.cache import cache

def norm_key(kind: str, sha256: str) -> str:
    return f"norm:{kind}:{sha256}"

def get_cached_normalization(kind: str, sha256: str):
    return cache.get(norm_key(kind, sha256))

def set_cached_normalization(kind: str, sha256: str, payload: dict, ttl: int = 24 * 3600):
    # payload: {"openapi_version": "3.0.3", "caps": [...]}
    cache.set(norm_key(kind, sha256), payload, timeout=ttl)
