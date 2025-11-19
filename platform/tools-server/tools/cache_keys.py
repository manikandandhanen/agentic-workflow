def cap_snapshot_key(tenant_id: int | str, team_id: int | str, active: bool = True) -> str:
    return f"mcp-registry:{tenant_id}:{team_id}:{1 if active else 0}"
