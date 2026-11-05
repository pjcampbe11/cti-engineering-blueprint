"""
sentinelone.py - SentinelOne Singularity adapter (REST, stdlib only).

Two APIs, two credentials:
  1. Management API  https://<tenant>.sentinelone.net/web/api/v2.1/...
     Header: Authorization: ApiToken <token>   (service user token, Viewer role for read)
     Used for: threats (alerts), agents (host context), response actions.
  2. Singularity Data Lake (SDL) PowerQuery  https://xdr.<region>.sentinelone.net/api/powerQuery
     Header: Authorization: Bearer <SDL Log Read key>
     Used for: EDR telemetry pivots (process, network, DNS, file events).

IMPORTANT - API lifecycle: SentinelOne deprecated legacy Deep Visibility and
S1QL 1.0 on Feb 15, 2026; legacy Deep Visibility APIs stop working on
Feb 15, 2027. Integrations on /web/api/v2.1/dv/init-query must migrate
(Long Running Query API / Saved Searches API, or SDL PowerQuery as used here).
Inventory your scripts for /dv/ endpoints now.

Storyline: S1 stitches related activity into a storyline ID. Pivoting on
src.process.storyline.id returns the whole story in one query, which is why
S1 pivots are usually one call instead of a tree walk.

SDL field names below follow the OCSF-style schema S1 uses
(src.process.*, tgt.process.*, dst.ip.address, event.type ...). Validate the
exact names in your SDL console before production - schema evolves.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from ..common import ThinAlert, HostContext, ProcessNode, NetConn, TokenBucket, http_json
from .base import EDRAdapter


def _q(v: str) -> str:
    """Quote a value for PowerQuery. Alert-derived strings are untrusted."""
    return "'" + str(v).replace("\\", "\\\\").replace("'", "\\'") + "'"


class SentinelOneAdapter(EDRAdapter):
    vendor = "sentinelone"

    def __init__(self, mgmt_url: str, api_token: str, sdl_url: str, sdl_key: str, **kw):
        super().__init__(**kw)
        self.mgmt = mgmt_url.rstrip("/")
        self.sdl = sdl_url.rstrip("/")
        self._mh = {"Authorization": f"ApiToken {api_token}"}
        self._sh = {"Authorization": f"Bearer {sdl_key}"}
        self.bucket = TokenBucket(rate_per_min=60)

    @classmethod
    def from_env(cls, **kw):
        return cls(os.environ["S1_MGMT_URL"], os.environ["S1_API_TOKEN"],
                   os.environ["S1_SDL_URL"], os.environ["S1_SDL_KEY"], **kw)

    # -------------------------------------------------------------- helpers
    def _mgmt(self, path: str, params: dict | None = None, method="GET", body=None) -> dict:
        return http_json(method, f"{self.mgmt}/web/api/v2.1/{path}", headers=self._mh,
                         params=params, body=body, bucket=self.bucket, purpose="s1-mgmt")

    def _pq(self, query: str, hours: int = 24) -> list[dict]:
        """Run a PowerQuery; convert the columns/values table into dicts."""
        now = datetime.now(timezone.utc)
        body = {"query": query,
                "startTime": (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "endTime": now.strftime("%Y-%m-%dT%H:%M:%SZ")}
        r = http_json("POST", f"{self.sdl}/api/powerQuery", headers=self._sh, body=body,
                      bucket=self.bucket, purpose="s1-powerquery")
        cols = [c["name"] for c in r.get("columns", [])]
        return [dict(zip(cols, row)) for row in r.get("values", [])]

    # ------------------------------------------------------------ interface
    def enrich_alert(self, alert: ThinAlert) -> ThinAlert:
        d = (self._mgmt("threats", {"ids": alert.alert_id}).get("data") or [{}])[0]
        ti, ag = d.get("threatInfo") or {}, d.get("agentRealtimeInfo") or {}
        alert.device_id = alert.device_id or ag.get("agentId")
        alert.host = alert.host or ag.get("agentComputerName")
        alert.sha256 = alert.sha256 or ti.get("sha256")
        alert.user = alert.user or ti.get("processUser")
        alert.cmdline = alert.cmdline or ti.get("maliciousProcessArguments")
        # Storyline is the best pivot key S1 gives you.
        alert.process_id = alert.process_id or ti.get("storyline")
        return alert

    def host_context(self, alert):
        a = (self._mgmt("agents", {"ids": alert.device_id}).get("data") or [{}])[0]
        return HostContext(device_id=alert.device_id, hostname=a.get("computerName", alert.host),
                           os=a.get("osName"), last_seen=a.get("lastActiveDate"),
                           ou_or_group=a.get("groupName"), external_ip=a.get("externalIp"),
                           tags=[t.get("key", "") for t in (a.get("tags") or {}).get("sentinelone", [])])

    def process_tree(self, alert, depth_up=4):
        """One storyline query returns every process creation in the story."""
        rows = self._pq(
            f"src.process.storyline.id = {_q(alert.process_id)} event.type = 'Process Creation' "
            "| columns src.process.uid, src.process.name, tgt.process.uid, tgt.process.name, "
            "tgt.process.cmdline, tgt.process.image.sha256, tgt.process.user, tgt.process.isSigned "
            "| limit 500", hours=24 * 7)
        nodes, seen = [], set()
        for r in rows:
            if r.get("src.process.uid") and r["src.process.uid"] not in seen:
                seen.add(r["src.process.uid"])
                nodes.append(ProcessNode(pid=r["src.process.uid"], name=r.get("src.process.name", "")))
            nodes.append(ProcessNode(pid=r.get("tgt.process.uid"), name=r.get("tgt.process.name", ""),
                                     cmdline=r.get("tgt.process.cmdline", ""),
                                     sha256=r.get("tgt.process.image.sha256"),
                                     user=r.get("tgt.process.user"), parent_pid=r.get("src.process.uid"),
                                     signed=r.get("tgt.process.isSigned")))
            seen.add(r.get("tgt.process.uid"))
        return nodes

    def network_for(self, alert, pids):
        rows = self._pq(
            f"src.process.storyline.id = {_q(alert.process_id)} "
            "(event.type = 'IP Connect' or event.type = 'DNS Resolved') "
            "| columns src.process.uid, dst.ip.address, dst.port.number, event.dns.request | limit 1000",
            hours=24 * 7)
        return [NetConn(pid=r.get("src.process.uid"), remote_ip=r.get("dst.ip.address") or "",
                        remote_port=r.get("dst.port.number"), domain=r.get("event.dns.request"),
                        direction="dns" if r.get("event.dns.request") else "outbound")
                for r in rows if not pids or r.get("src.process.uid") in pids]

    def hash_prevalence(self, sha256, days=30):
        rows = self._pq(f"tgt.process.image.sha256 = {_q(sha256)} "
                        "| group hosts = estimate_distinct(agent.uuid)", hours=24 * days)
        return int(rows[0].get("hosts", 0)) if rows else 0

    def _contain(self, device_id):
        # "Disconnect from network" = network quarantine in S1 terms.
        return self._mgmt("agents/actions/disconnect", method="POST",
                          body={"filter": {"ids": [device_id]}})
