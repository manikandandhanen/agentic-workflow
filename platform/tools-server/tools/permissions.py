from rest_framework.permissions import BasePermission, IsAuthenticated
from accounts.auth import ServicePrincipal

class IsTenantMember(IsAuthenticated):
    """
    Basic guard: user must be authenticated and belong to a tenant.
    """
    def has_permission(self, request, view):
        return super().has_permission(request, view) and getattr(request.user, "tenant_id", None) is not None


class IsTenantMemberOrServiceToken(BasePermission):
    """
    Allows:
      - Authenticated human users with a tenant (your existing IsTenantMember)
      - Service tokens (ServicePrincipal) scoped to the same tenant and scope
    """
    required_scope = "capabilities:read"

    def has_permission(self, request, view):
        retval = False
        u = request.user
        # print("USER | SP: >>>>>>>>>>> ", u.__dict__)
        # Service token path
        if isinstance(u, ServicePrincipal):
            if not u.tenant_id:
                return False
            scope = getattr(view, "required_scope", getattr(self, "required_scope", None))
            retval = (scope is None) or (scope in (u.scopes or []))
            print("IsTenantMemberOrServiceToken -> SP:", retval)
            return retval
        # Human user path
        retval = bool(getattr(u, "is_authenticated", False) and getattr(u, "tenant_id", None) is not None)
        print("IsTenantMemberOrServiceToken -> User:", retval)
        return retval