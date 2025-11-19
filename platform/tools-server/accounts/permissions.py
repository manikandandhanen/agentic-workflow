# accounts/permissions.py
from .models import Membership, Tool, VisibilityScope

def user_has_action_on_resource(user, *, team=None, resource:str, action:str) -> bool:
    """
    Check if user has a given (resource, action) through membership roles.
    If team is provided, check via that team membership.
    """
    if not user.is_authenticated:
        return False

    # Superusers shortcut
    if getattr(user, "is_superuser", False):
        return True

    # Gather permissions from all memberships if team not specified
    qs = Membership.objects.filter(user=user).prefetch_related("roles__permissions")
    if team is not None:
        qs = qs.filter(team=team)

    for membership in qs:
        for role in membership.roles.all():
            if role.permissions.filter(resource=resource, action=action).exists():
                return True
    return False


def user_can_see_tool(user, tool: Tool) -> bool:
    if tool.scope == VisibilityScope.GLOBAL:
        return True
    if tool.scope == VisibilityScope.TENANT:
        return user.tenant_id and tool.tenant_id == user.tenant_id
    if tool.scope == VisibilityScope.TEAM:
        return Membership.objects.filter(user=user, team__in=tool.teams.all()).exists()
    return False


def user_can_execute_tool(user, tool: Tool, team=None) -> bool:
    """
    Composite: visibility + action permission check.
    """
    if not user_can_see_tool(user, tool):
        return False
    return user_has_action_on_resource(
        user,
        team=team,
        resource=tool.required_resource,
        action=tool.required_action,
    )
