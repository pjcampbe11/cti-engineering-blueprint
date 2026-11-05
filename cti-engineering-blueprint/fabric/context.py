"""
context.py - asset, identity and change-window context.

This is the information that separates "attacker" from "admin with bad
habits". It normally comes from:
  * CMDB / asset inventory (ServiceNow CMDB, cloud inventories, Wiz)
  * IAM / directory exports (privileged groups, PAW and jump-host lists, VIPs)
  * Change management (approved change windows per host / CI)
In Splunk ES these become the Asset & Identity framework lookups; here we read
the same shape from CSV so the logic is portable and testable.

Files (see mocks/ for examples):
  assets.csv      hostname, criticality(1-5), role, env, owner, is_admin_host, tags
  identities.csv  user, privileged(true/false), groups, vip(true/false)
  changes.csv     change_id, hostname, start_iso, end_iso, description
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path


def _rows(p: Path) -> list[dict]:
    if not p.exists():
        return []
    with p.open() as fh:
        return list(csv.DictReader(fh))


def _ts(v: str) -> datetime:
    return datetime.fromisoformat(v.replace("Z", "+00:00"))


class Context:
    def __init__(self, folder: Path):
        folder = Path(folder)
        self.assets = {r["hostname"].lower(): r for r in _rows(folder / "assets.csv")}
        self.ids = {r["user"].lower(): r for r in _rows(folder / "identities.csv")}
        self.changes = _rows(folder / "changes.csv")

    def for_alert(self, host: str, user: str | None, when: str | None) -> dict:
        a = self.assets.get((host or "").lower(), {})
        u = self.ids.get((user or "").lower().split("\\")[-1], {})
        now = _ts(when) if when else datetime.now(timezone.utc)
        chg = [c for c in self.changes if c["hostname"].lower() == (host or "").lower()
               and _ts(c["start_iso"]) <= now <= _ts(c["end_iso"])]
        return {
            "asset_known": bool(a),
            "criticality": int(a.get("criticality") or 3),
            "role": a.get("role"),
            "is_admin_host": str(a.get("is_admin_host", "")).lower() == "true",
            "user_privileged": str(u.get("privileged", "")).lower() == "true",
            "user_vip": str(u.get("vip", "")).lower() == "true",
            "user_known": bool(u),
            "change_window": chg[0]["change_id"] if chg else None,
        }
