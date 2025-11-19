from drf_spectacular.extensions import OpenApiAuthenticationExtension
from accounts.auth import BearerServiceTokenAuthentication

class BearerServiceTokenAuthScheme(OpenApiAuthenticationExtension):
    target_class = 'accounts.auth.BearerServiceTokenAuthentication'
    name = 'BearerServiceTokenAuth'

    def get_security_definition(self, auto_schema):
        return {
            'type': 'http',
            'scheme': 'bearer',
            'bearerFormat': 'JWT',
            'description': 'Custom Bearer token for service authentication.'
        }
