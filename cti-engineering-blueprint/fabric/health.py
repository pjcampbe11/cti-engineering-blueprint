"""
health.py - is every connector alive, authenticated and current?

Integrations rarely fail loudly. A rotated API key, an expired OAuth secret,
a feed that silently stops updating, a TAXII poll stuck on the same
`added_after` - each leaves the dashboards green and the intel stale.

For each connector we record:
  auth_ok      - a cheap authenticated call succeeded
  last_data    - newest record timestamp seen from that source
  lag_minutes  - now - last_data
  status       - OK / LAGGING / DOWN against a per-connector SLO

Ship the result to Splunk (HEC) and alert on status != OK. Pair every
connector with an owner and a runbook entry; "who fixes this at 2 a.m." is
part of the integration design, not an afterthought.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable


def check(name: str, ping: Callable[[], str | None], slo_minutes: int) -> dict:
    """ping() performs a cheap authenticated call and returns the newest data
    timestamp (ISO) it can see, or None if the source has no notion of one."""
    now = datetime.now(timezone.utc)
    try:
        last = ping()
        lag = None
        if last:
            lag = round((now - datetime.fromisoformat(last.replace("Z", "+00:00"))).total_seconds() / 60, 1)
        status = "OK" if lag is None or lag <= slo_minutes else "LAGGING"
        return {"connector": name, "auth_ok": True, "last_data": last, "lag_minutes": lag,
                "slo_minutes": slo_minutes, "status": status}
    except Exception as e:  # noqa: BLE001
        return {"connector": name, "auth_ok": False, "error": f"{type(e).__name__}: {str(e)[:200]}",
                "slo_minutes": slo_minutes, "status": "DOWN"}
