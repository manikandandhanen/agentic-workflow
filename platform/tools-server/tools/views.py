from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
import requests
from drf_spectacular.utils import extend_schema
from rest_framework import serializers

# Create your views here.
def home(request):
    return render(request, 'tools/index.html', {})

class ListMCPToolsResponseSerializer(serializers.Serializer):
    # Define fields as per expected response structure
    # This is a fallback, you may want to refine this based on actual data
    detail = serializers.CharField(required=False)
    # Add more fields as needed

class ListMCPTools(APIView):
    @extend_schema(
        responses=ListMCPToolsResponseSerializer,
        description="List MCP tools for the tenant and team."
    )
    def get(self, request):
        mcp_tools_root_url = "http://mcp-server:8080/tools"
        tenant = request.user.tenant
        if not tenant:
            return Response({"detail": "The tenant must be provided via service token or user membership."}, status=400)

        team = tenant.teams.first() # assuming the first team is the default one
        if not team:
            return Response({"detail": "No team found for the tenant."}, status=400)
        mcp_tools_url = f"{mcp_tools_root_url}?tenant={tenant}&team={team.slug}&active=true"
        auth_header = request.headers.get("Authorization")
        resp = requests.get(mcp_tools_url, headers={"Authorization": auth_header} if auth_header else {})
        data = resp.json()
        return Response(data)