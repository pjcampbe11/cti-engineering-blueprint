"""
crowdstrike.py - CrowdStrike Falcon adapter using FalconPy (crowdstrike-falconpy).

FalconPy is CrowdStrike's official Python SDK. It handles OAuth2 token
creation and refresh; you create an API client in the Falcon console with only
the scopes you need and pass client_id/client_secret (and base_url for
non-US-1 clouds).

Scopes this adapter needs (read-only unless you enable containment):
  Alerts: READ           -> pull the full alert behind the thin SIEM record
  Hosts: READ            -> host context; Hosts: WRITE only for containment
  NGSIEM: READ + WRITE   -> run CQL queries over endpoint telemetry
                            (WRITE is required to *start* a query job)

Telemetry access path - why NGSIEM:
  Falcon endpoint events (ProcessRollup2, NetworkConnectIP4, DnsRequest...)
  are queryable with CQL in Next-Gen SIEM / LogScale repositories.
  `investigate_view` holds endpoint events (requires Falcon Insight XDR);
  `search-all` covers all data incl. third-party. Queries are async jobs:
  start_search -> poll get_search_status until done -> read events.
  CQL supports ?param placeholders with an `arguments` map - use them instead
  of string-building queries (avoids query injection from alert fields).

Key event fields (verify against your tenant's event dictionary):
  ProcessRollup2: aid, TargetProcessId, ParentProcessId, ImageFileName,
                  CommandLine, SHA256HashData, UserName, ProcessStartTime
  NetworkConnectIP4: aid, ContextProcessId, RemoteAddressIP4, RemotePort
  DnsRequest:     aid, ContextProcessId, DomainName
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone

from ..common import ThinAlert, HostContext, ProcessNode, NetConn, audit
from .base import EDRAdapter

REPO = os.environ.get("CS_NGSIEM_REPO", "investigate_view")


class CrowdStrikeAdapter(EDRAdapter):
    vendor = "crowdstrike"

    def __init__(self, alerts, hosts, ngsiem, *, poll_s: float = 5, timeout_s: float = 120, **kw):
        """Takes already-constructed FalconPy service objects so tests can
        inject fakes. from_env() builds the real ones."""
        super().__init__(**kw)
        self.alerts, self.hosts, self.ngsiem = alerts, hosts, ngsiem
        self.poll_s, self.timeout_s = poll_s, timeout_s

    @classmethod
    def from_env(cls, **kw) -> "CrowdStrikeAdapter":
        from falconpy import Alerts, Hosts, NGSIEM, OAuth2  # lazy: SDK optional
        auth = OAuth2(client_id=os.environ["FALCON_CLIENT_ID"],
                      client_secret=os.environ["FALCON_CLIENT_SECRET"],
                      base_url=os.environ.get("FALCON_BASE_URL", "auto"))
        # One OAuth2 object shared by every service class = one token.
        return cls(Alerts(auth_object=auth), Hosts(auth_object=auth), NGSIEM(auth_object=auth), **kw)

    # ------------------------------------------------------------- helpers
    def _cql(self, query: str, args: dict, hours: int = 24) -> list[dict]:
        """Run a CQL job and wait for it. Stops the job on timeout so we do not
        leave expensive queries running on the tenant."""
        start = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        audit("CQL", f"crowdstrike:{REPO}", query.split("|")[0][:80])
        r = self.ngsiem.start_search(repository=REPO, query_string=query, arguments=args, start=start)
        body = r.get("resources") or r.get("body") or {}
        job = body.get("id")
        if not job:
            raise RuntimeError(f"NGSIEM start failed: {r.get('status_code')} {r.get('body') or r.get('errors')}")
        waited = 0.0
        while waited < self.timeout_s:
            s = self.ngsiem.get_search_status(repository=REPO, id=job)
            sb = s.get("body") or s.get("resources") or {}
            if sb.get("done"):
                return sb.get("events", [])
            time.sleep(self.poll_s)
            waited += self.poll_s
        self.ngsiem.stop_search(repository=REPO, id=job)
        raise TimeoutError("NGSIEM query timed out - narrow the time window")

    # ----------------------------------------------------------- interface
    def enrich_alert(self, alert: ThinAlert) -> ThinAlert:
        """Fill gaps in the thin alert from the full Falcon alert record."""
        r = self.alerts.get_alerts_v2(composite_ids=[alert.alert_id])
        res = (r.get("body") or {}).get("resources") or []
        if res:
            a = res[0]
            dev = a.get("device") or {}
            alert.device_id = alert.device_id or dev.get("device_id")
            alert.host = alert.host or dev.get("hostname")
            alert.user = alert.user or a.get("user_name")
            alert.sha256 = alert.sha256 or a.get("sha256")
            alert.cmdline = alert.cmdline or a.get("cmdline")
            alert.tactic = alert.tactic or a.get("tactic")
            alert.technique = alert.technique or a.get("technique_id")
            # Falcon alerts expose the process as a "triggering process graph"
            # / process ID; keep both for the CQL pivot.
            alert.process_id = alert.process_id or str(a.get("process_id") or a.get("local_process_id") or "")
        return alert

    def host_context(self, alert):
        r = self.hosts.get_device_details(ids=[alert.device_id])
        d = ((r.get("body") or {}).get("resources") or [{}])[0]
        return HostContext(device_id=alert.device_id, hostname=d.get("hostname", alert.host),
                           os=d.get("os_version") or d.get("platform_name"),
                           last_seen=d.get("last_seen"), ou_or_group=d.get("ou", [None])[0] if d.get("ou") else None,
                           tags=list(d.get("tags") or []), external_ip=d.get("external_ip"))

    def _proc(self, aid: str, pid: str) -> ProcessNode | None:
        ev = self._cql("#event_simpleName=ProcessRollup2 aid=?aid TargetProcessId=?pid "
                       "| tail(1) | table([TargetProcessId, ParentProcessId, ImageFileName, "
                       "CommandLine, SHA256HashData, UserName, ProcessStartTime])",
                       {"aid": aid, "pid": pid}, hours=24 * 7)
        if not ev:
            return None
        e = ev[0]
        return ProcessNode(pid=str(e.get("TargetProcessId")), name=str(e.get("ImageFileName", "")).split("\\")[-1],
                           cmdline=e.get("CommandLine", ""), sha256=e.get("SHA256HashData"),
                           user=e.get("UserName"), parent_pid=str(e.get("ParentProcessId") or "") or None,
                           start_time=str(e.get("ProcessStartTime") or ""))

    def process_tree(self, alert, depth_up=4):
        """Walk up the ancestry, then pull direct children of the target."""
        nodes, pid = [], alert.process_id
        for _ in range(depth_up + 1):
            if not pid:
                break
            n = self._proc(alert.device_id, pid)
            if not n:
                break
            nodes.insert(0, n)
            pid = n.parent_pid
        if alert.process_id:
            kids = self._cql("#event_simpleName=ProcessRollup2 aid=?aid ParentProcessId=?pid "
                             "| table([TargetProcessId, ImageFileName, CommandLine, SHA256HashData, UserName])",
                             {"aid": alert.device_id, "pid": alert.process_id})
            for e in kids:
                nodes.append(ProcessNode(pid=str(e.get("TargetProcessId")),
                                         name=str(e.get("ImageFileName", "")).split("\\")[-1],
                                         cmdline=e.get("CommandLine", ""), sha256=e.get("SHA256HashData"),
                                         user=e.get("UserName"), parent_pid=alert.process_id))
        return nodes

    def network_for(self, alert, pids):
        out = []
        for pid in pids:
            for e in self._cql("#event_simpleName=NetworkConnectIP4 aid=?aid ContextProcessId=?pid "
                               "| table([ContextProcessId, RemoteAddressIP4, RemotePort])",
                               {"aid": alert.device_id, "pid": pid}):
                out.append(NetConn(pid=pid, remote_ip=e.get("RemoteAddressIP4"),
                                   remote_port=int(e.get("RemotePort") or 0)))
            for e in self._cql("#event_simpleName=DnsRequest aid=?aid ContextProcessId=?pid "
                               "| table([DomainName])", {"aid": alert.device_id, "pid": pid}):
                out.append(NetConn(pid=pid, remote_ip="", domain=e.get("DomainName"), direction="dns"))
        return out

    def hash_prevalence(self, sha256, days=30):
        ev = self._cql("#event_simpleName=ProcessRollup2 SHA256HashData=?sha "
                       "| count(aid, distinct=true, as=hosts)", {"sha": sha256}, hours=24 * days)
        return int(ev[0].get("hosts", 0)) if ev else 0

    def _contain(self, device_id):
        return self.hosts.perform_action(action_name="contain", ids=[device_id])
