from django.shortcuts import render
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.conf import settings

from .jwt import create_n8n_sso_token

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def n8n_sso_url(request):
    user = request.user
    sso_token = create_n8n_sso_token(user)

    base_url = getattr(settings, "N8N_EMBED_URL", "http://localhost:8090/")
    if not base_url.endswith("/"):
        base_url += "/"

    url = f"{base_url}rest/workflows?sso={sso_token}"

    return Response({"url": url})