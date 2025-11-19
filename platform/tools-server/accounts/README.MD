# Accounts App

The **Accounts** app provides **multi-tenant, team-based RBAC** on top of Django + Djoser + JWT (SimpleJWT).  
It is the foundation for authentication and authorization in the Schema-driven MCP platform.

---

## Features

- **Custom User model**
  - Email login (no username).
  - Linked to a `Tenant`.
  - Users can belong to multiple `Teams`.

- **Tenant / Team hierarchy**
  - `Tenant` → has multiple `Teams`.
  - `Team` → has many `Memberships`.

- **Roles & Permissions**
  - `Role` = named bundle of `Permissions`.
  - Permissions are simple **CRUD+EXECUTE** actions on a resource.
    - example of permission creation: 
        - `tool:execute`, `capability:retrieve`, `schema:update`
  - Users gain effective permissions via **Membership → Roles → Permissions**.

- **Tool visibility**
  - Tools can be scoped at **Team**, **Tenant**, or **Global** level.
  - Execution requires both **visibility** and **permission**.

- **JWT Integration**
  - Uses **Djoser** + **SimpleJWT**.
  - Access tokens include tenant, teams, and role claims.

---

## Models Overview

```text
Tenant
 └── Team
      └── Membership (User + Team + Roles)
           └── Role(s)
                └── Permission(s)

Tool (scope = team | tenant | global)
```

## Typical Usage Patterns

- **Check if a user can execute a tool**
```python
from accounts.permissions import user_can_execute_tool
from accounts.models import Tool

tool = Tool.objects.get(provider="salesforce", name="account.get", tenant=user.tenant)
if user_can_execute_tool(user, tool, team=my_team):
    print("✅ User is allowed to execute this tool")
else:
    print("⛔ Not allowed")

```

- **Filter tools visible to a user**

```python
from django.db import models
from accounts.models import Tool, VisibilityScope

visible_tools = Tool.objects.filter(
    models.Q(scope=VisibilityScope.GLOBAL)
    | models.Q(scope=VisibilityScope.TENANT, tenant=user.tenant)
    | models.Q(scope=VisibilityScope.TEAM, teams__memberships__user=user)
).distinct()

```

- **Check if a user has a specific permission**

```python
from accounts.permissions import user_has_action_on_resource
allowed = user_has_action_on_resource(
    user,
    team=my_team,
    resource="tool",
    action="execute"
)
```

- **Issue JWT with embedded roles/teams**

```json
{
  "user_id": 1,
  "email": "alice@example.com",
  "tenant": {"id": 10, "slug": "acme"},
  "teams": [{"id": 5, "slug": "devops"}],
  "roles": ["admin", "reader"],
  "exp": 1735647382,
  "jti": "..."
}
```

## Seeding Permissions
```python
DEFAULT_RESOURCES = ["tool", "capability", "schema", "team", "role"]
DEFAULT_ACTIONS = ["create", "retrieve", "update", "delete", "execute"]

from accounts.models import Permission
for r in DEFAULT_RESOURCES:
    for a in DEFAULT_ACTIONS:
        Permission.objects.get_or_create(resource=r, action=a)

```

## Admin UI

- Manage Tenants, Teams, Users, Roles, Permissions, and Tools via Django Admin.
- Memberships can be assigned roles via multi-select.

## Extensibility

- Add custom resources to Permission.
- Define prebuilt roles (e.g., Admin, Approver, Reader).
- Extend Tool to include additional metadata (provider, version, endpoint).
- Ver.1 assumes that memberships are in-tenant. If a user must join teams across different tenants, then:
    - remove the tenant constraint from User.tenant semantics 
    - ensure cross-tenant checks when issuing JWTs & evaluating permissions.

## Next Steps

- Add DRF endpoints for teams, roles, memberships.
- Seed common roles (admin, approver, reader).
- Write pytest tests for user_can_execute_tool and user_can_see_tool.