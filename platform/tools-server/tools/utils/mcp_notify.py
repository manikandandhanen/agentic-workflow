from __future__ import annotations
import time
import requests
from django.conf import settings
from typing import Iterable

def notify_capabilities_changed(tenant_slug: str, team_ids: Iterable[int] | None = None, forced_capset: int | None = None):
    """
    POST a capabilities.changed webhook to each configured MCP endpoint.
    If team_ids is None, we notify just the owner team(s) or fall back to '0' meaning 'any team'.
    forced_capset: if provided, use this as cap_set_id; else use epoch seconds.
    """
    print(f"CALLED Notifying MCPs of capability changes for tenant={tenant_slug} team_ids={team_ids} forced_capset={forced_capset}")
    cap_set_id = forced_capset or int(time.time())
    urls = getattr(settings, "MCP_WEBHOOK_URLS", [])
    payloads = []

    if not team_ids:
        team_ids = [0]  # mcp side may ignore team=0 and just reload

    for team_id in team_ids:
        payloads.append({"tenant": tenant_slug, "team": str(team_id), "cap_set_id": cap_set_id})

    for url in urls:
        u = url.strip()
        if not u:
            continue
        for p in payloads:
            try:
                requests.post(u, json=p, timeout=5)
            except Exception as e:
                print(f"WARNING: failed to notify MCP at {u} for tenant={tenant_slug} team={p['team']} cap_set_id={cap_set_id}: {e}")
                # best-effort notify
                pass
