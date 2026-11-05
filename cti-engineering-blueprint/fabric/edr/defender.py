"""
defender.py - Microsoft Defender for Endpoint / Defender XDR adapter via the
Microsoft Graph security API (advanced hunting).

  Token:  POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token
          grant_type=client_credentials, scope=https://graph.microsoft.com/.default
  Hunt:   POST https://graph.microsoft.com/v1.0/security/runHuntingQuery
          body {"Query": "<KQL>", "Timespan": "P7D"}   permission ThreatHunting.Read.All
  Alerts: GET  https://graph.microsoft.com/v1.0/security/alerts_v2/{id}

Limits to design around (Microsoft docs): about 45 calls/minute and 1,500/hour,
10 minutes of query run time per hour, 3 hours per day, 200 s per request,
50 MB result size. The old api.security.microsoft.com advanced hunting
endpoints are deprecated - build on Graph.

Advanced hunting keeps 30 days of raw data. Rows in DeviceProcessEvents carry
the process AND its initiating (parent) process, so one KQL query gives you two
levels of the tree.
"""

from __future__ import annotations

import os
import time
import urllib.parse

from ..common import ThinAlert, HostContext, ProcessNode, NetConn, TokenBucket, http_json
from .base import EDRAdapter

GRAPH = "https://graph.microsoft.com/v1.0"


def _k(v: str) -> str:
    """Escape a string literal for KQL (single-quoted)."""
    return "'" + str(v).replace("\\", "\\\\").replace("'", "\\'") + "'"


class DefenderAdapter(EDRAdapter):
    vendor = "defender"

    def __init__(self, tenant: str, client_id: str, client_secret: str, graph: str = GRAPH,
                 token_url: str | None = None, **kw):
        super().__init__(**kw)
        self.graph = graph.rstrip("/")
        self.token_url = token_url or f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        self.cid, self.secret = client_id, client_secret
        self._tok, self._exp = None, 0.0
        self.bucket = TokenBucket(rate_per_min=30)   # below the ~45/min ceiling

    @classmethod
    def from_env(cls, **kw):
        return cls(os.environ["AZ_TENANT_ID"], os.environ["AZ_CLIENT_ID"], os.environ["AZ_CLIENT_SECRET"], **kw)

    def _token(self) -> str:
        if self._tok and time.time() < self._exp - 60:
            return self._tok
        form = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": self.cid,
                                       "client_secret": self.secret,
                                       "scope": "https://graph.microsoft.com/.default"}).encode()
        r = http_json("POST", self.token_url, body=form,
                      headers={"Content-Type": "application/x-www-form-urlencoded"}, purpose="aad-token")
        self._tok, self._exp = r["access_token"], time.time() + int(r.get("expires_in", 3600))
        return self._tok

    def hunt(self, kql: str, timespan: str = "P7D") -> list[dict]:
        r = http_json("POST", f"{self.graph}/security/runHuntingQuery",
                      headers={"Authorization": f"Bearer {self._token()}"},
                      body={"Query": kql, "Timespan": timespan}, bucket=self.bucket, purpose="mde-hunt")
        return r.get("results", [])

    # ------------------------------------------------------------ interface
    def host_context(self, alert):
        rows = self.hunt(f"DeviceInfo | where DeviceId == {_k(alert.device_id)} "
                         "| summarize arg_max(Timestamp, *) | project DeviceName, OSPlatform, "
                         "OSVersion, MachineGroup, DeviceCategory, PublicIP, Timestamp")
        d = rows[0] if rows else {}
        return HostContext(device_id=alert.device_id, hostname=d.get("DeviceName", alert.host),
                           os=f"{d.get('OSPlatform', '')} {d.get('OSVersion', '')}".strip() or None,
                           last_seen=d.get("Timestamp"), ou_or_group=d.get("MachineGroup"),
                           external_ip=d.get("PublicIP"))

    def process_tree(self, alert, depth_up=4):
        """Walk up via InitiatingProcessId; each row yields process + parent."""
        nodes, pid = [], alert.process_id
        for _ in range(depth_up + 1):
            if not pid:
                break
            rows = self.hunt(
                f"DeviceProcessEvents | where DeviceId == {_k(alert.device_id)} and ProcessId == {int(pid)} "
                "| top 1 by Timestamp desc | project ProcessId, FileName, ProcessCommandLine, SHA256, "
                "AccountName, InitiatingProcessId, InitiatingProcessFileName, ProcessCreationTime")
            if not rows:
                break
            r = rows[0]
            nodes.insert(0, ProcessNode(pid=str(r["ProcessId"]), name=r.get("FileName", ""),
                                        cmdline=r.get("ProcessCommandLine", ""), sha256=r.get("SHA256"),
                                        user=r.get("AccountName"),
                                        parent_pid=str(r.get("InitiatingProcessId") or "") or None,
                                        start_time=r.get("ProcessCreationTime")))
            pid = r.get("InitiatingProcessId")
        if alert.process_id:
            for r in self.hunt(
                    f"DeviceProcessEvents | where DeviceId == {_k(alert.device_id)} "
                    f"and InitiatingProcessId == {int(alert.process_id)} "
                    "| project ProcessId, FileName, ProcessCommandLine, SHA256, AccountName | take 100"):
                nodes.append(ProcessNode(pid=str(r["ProcessId"]), name=r.get("FileName", ""),
                                         cmdline=r.get("ProcessCommandLine", ""), sha256=r.get("SHA256"),
                                         user=r.get("AccountName"), parent_pid=str(alert.process_id)))
        return nodes

    def network_for(self, alert, pids):
        if not pids:
            return []
        plist = ",".join(str(int(p)) for p in pids if str(p).isdigit())
        rows = self.hunt(f"DeviceNetworkEvents | where DeviceId == {_k(alert.device_id)} "
                         f"and InitiatingProcessId in ({plist}) "
                         "| project InitiatingProcessId, RemoteIP, RemotePort, RemoteUrl | take 500")
        return [NetConn(pid=str(r["InitiatingProcessId"]), remote_ip=r.get("RemoteIP", ""),
                        remote_port=r.get("RemotePort"), domain=r.get("RemoteUrl") or None) for r in rows]

    def hash_prevalence(self, sha256, days=30):
        rows = self.hunt(f"DeviceProcessEvents | where SHA256 == {_k(sha256)} "
                         "| summarize hosts = dcount(DeviceId)", timespan=f"P{min(days, 30)}D")
        return int(rows[0]["hosts"]) if rows else 0

    def _contain(self, device_id):
        # Isolation is an MDE API action (api.securitycenter.microsoft.com
        # /api/machines/{id}/isolate) with Machine.Isolate permission - a
        # separate app registration from the read-only hunting app is the
        # right least-privilege design.
        raise NotImplementedError("use a separate, approval-gated MDE response app")
