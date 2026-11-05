"""
carbonblack.py - VMware/Broadcom Carbon Black Cloud adapter using the official
Carbon Black Cloud Python SDK (`carbon-black-cloud-sdk`, import name cbc_sdk).

Auth: an API key of type "Custom" with an access level granting the APIs
below; token format is "API_SECRET_KEY/API_ID", plus your org_key and the
regional URL (e.g. https://defense.conferdeploy.net). The SDK also supports
credential files and other credential providers - prefer those or a vault over
environment variables in production.

SDK concepts used:
  * api.select(Model) returns a lazy query; iterate to execute.
  * Process search (Enterprise EDR) keys processes by process_guid, which is
    globally unique - far better than OS PIDs, which recycle.
  * Process objects expose .parents, .children, .tree() and .events(event_type=...)
    for netconn / filemod / regmod / modload pivots.
  * Device.quarantine(True) is the containment action.

The SDK caches results and handles async process searches for you, which is
exactly why you use a vendor client rather than raw REST when one exists.
"""

from __future__ import annotations

import os

from ..common import ThinAlert, HostContext, ProcessNode, NetConn, audit
from .base import EDRAdapter


def _first(v):
    """CBC returns several process fields as lists (cmdline, username)."""
    return v[0] if isinstance(v, list) and v else v


class CarbonBlackAdapter(EDRAdapter):
    vendor = "carbonblack"

    def __init__(self, api, **kw):
        super().__init__(**kw)
        self.api = api  # a cbc_sdk.CBCloudAPI (or a test fake with the same surface)

    @classmethod
    def from_env(cls, **kw):
        from cbc_sdk import CBCloudAPI
        return cls(CBCloudAPI(url=os.environ["CBC_URL"], token=os.environ["CBC_TOKEN"],
                              org_key=os.environ["CBC_ORG_KEY"]), **kw)

    def _models(self):
        from cbc_sdk.platform import Alert, Device, Process
        return Alert, Device, Process

    def enrich_alert(self, alert: ThinAlert) -> ThinAlert:
        Alert, _, _ = self._models()
        a = self.api.select(Alert, alert.alert_id)
        alert.device_id = alert.device_id or str(getattr(a, "device_id", "") or "")
        alert.host = alert.host or getattr(a, "device_name", None)
        alert.user = alert.user or getattr(a, "device_username", None)
        alert.process_id = alert.process_id or getattr(a, "process_guid", None)
        alert.sha256 = alert.sha256 or getattr(a, "process_sha256", None)
        alert.tactic = alert.tactic or _first(getattr(a, "attack_tactic", None))
        return alert

    def host_context(self, alert):
        _, Device, _ = self._models()
        d = self.api.select(Device, int(alert.device_id))
        return HostContext(device_id=str(alert.device_id), hostname=getattr(d, "name", alert.host),
                           os=f"{getattr(d, 'os', '')} {getattr(d, 'os_version', '')}".strip(),
                           last_seen=getattr(d, "last_contact_time", None),
                           ou_or_group=getattr(d, "policy_name", None),
                           external_ip=getattr(d, "last_external_ip_address", None))

    def _node(self, p, parent=None) -> ProcessNode:
        return ProcessNode(pid=getattr(p, "process_guid", ""),
                           name=str(getattr(p, "process_name", "")).split("\\")[-1],
                           cmdline=_first(getattr(p, "process_cmdline", "")) or "",
                           sha256=_first(getattr(p, "process_sha256", None)),
                           user=_first(getattr(p, "process_username", None)),
                           parent_pid=parent or getattr(p, "parent_guid", None),
                           start_time=getattr(p, "process_start_time", None))

    def process_tree(self, alert, depth_up=4):
        _, _, Process = self._models()
        audit("CBC", "process_search", f"tree {alert.process_id}")
        procs = list(self.api.select(Process).where(process_guid=alert.process_id))
        if not procs:
            return []
        target = procs[0]
        nodes = [self._node(target)]
        # Ancestors: follow .parents (SDK returns the parent chain it knows).
        cur, hops = target, 0
        while hops < depth_up:
            parents = getattr(cur, "parents", None) or []
            parent = parents[0] if isinstance(parents, list) and parents else (parents or None)
            if not parent or not getattr(parent, "process_guid", None):
                break
            nodes.insert(0, self._node(parent))
            cur, hops = parent, hops + 1
        for c in getattr(target, "children", None) or []:
            nodes.append(self._node(c, parent=target.process_guid))
        return nodes

    def network_for(self, alert, pids):
        _, _, Process = self._models()
        out = []
        for guid in pids:
            for p in self.api.select(Process).where(process_guid=guid):
                for ev in p.events(event_type="netconn"):
                    out.append(NetConn(pid=guid,
                                       remote_ip=getattr(ev, "netconn_remote_ipv4", None)
                                       or getattr(ev, "netconn_ipv4", "") or "",
                                       remote_port=getattr(ev, "netconn_remote_port", None)
                                       or getattr(ev, "netconn_port", None),
                                       domain=getattr(ev, "netconn_domain", None)))
                break
        return out

    def hash_prevalence(self, sha256, days=30):
        _, _, Process = self._models()
        q = self.api.select(Process).where(process_hash=sha256)
        devices = set()
        for i, p in enumerate(q):
            devices.add(getattr(p, "device_id", None))
            if i > 2000:   # cap work; prevalence above this is "common" anyway
                break
        return len(devices - {None})

    def _contain(self, device_id):
        _, Device, _ = self._models()
        d = self.api.select(Device, int(device_id))
        d.quarantine(True)
        return {"quarantined": device_id}
