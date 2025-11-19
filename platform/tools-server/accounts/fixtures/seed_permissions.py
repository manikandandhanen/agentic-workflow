DEFAULT_RESOURCES = ["tool", "capability", "schema", "team", "role"]
DEFAULT_ACTIONS = ["create", "retrieve", "update", "delete", "execute"]

def seed():
    from accounts.models import Permission
    for r in DEFAULT_RESOURCES:
        for a in DEFAULT_ACTIONS:
            Permission.objects.get_or_create(resource=r, action=a)
