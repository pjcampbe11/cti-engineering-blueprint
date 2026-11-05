"""
base.py - the EDR adapter contract, plus a mock adapter for offline demos.

The five questions every pivot asks of an EDR, regardless of vendor:
  1. host_context      - what is this machine (OS, group/OU, tags, last seen)?
  2. process_tree      - who launched the flagged process, and what did it launch?
  3. network_for       - where did those processes talk to (IPs, ports, domains)?
  4. hash_prevalence   - how many hosts have ever run this binary? (rare = interesting)
  5. contain           - isolate the host (gated: approval reference required)

These map to telemetry the EDR already stores and you already pay for. The
SIEM only needs enough fields to route the alert; the depth stays in the EDR
and is fetched on demand.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path

from ..common import ThinAlert, HostContext, ProcessNode, NetConn, require_approval


class EDRAdapter(ABC):
    vendor = "abstract"

    def __init__(self, allow_response: bool = False):
        # Response actions are off unless explicitly enabled per deployment.
        self.allow_response = allow_response

    @abstractmethod
    def host_context(self, alert: ThinAlert) -> HostContext: ...

    @abstractmethod
    def process_tree(self, alert: ThinAlert, depth_up: int = 4) -> list[ProcessNode]: ...

    @abstractmethod
    def network_for(self, alert: ThinAlert, pids: list[str]) -> list[NetConn]: ...

    @abstractmethod
    def hash_prevalence(self, sha256: str, days: int = 30) -> int: ...

    def contain(self, device_id: str, approval_ref: str | None = None) -> dict:
        require_approval(self.allow_response, approval_ref, f"{self.vendor}:contain:{device_id}")
        return self._contain(device_id)

    def _contain(self, device_id: str) -> dict:
        raise NotImplementedError


class MockEDR(EDRAdapter):
    """Serves scenario data from mocks/scenarios.json so the pivot pipeline
    can be demonstrated end to end without any vendor tenant."""

    def __init__(self, vendor: str, scenario_file: Path, **kw):
        super().__init__(**kw)
        self.vendor = f"mock-{vendor}"
        self.data = json.loads(Path(scenario_file).read_text())

    def _s(self, alert: ThinAlert) -> dict:
        return self.data["scenarios"][alert.alert_id]

    def host_context(self, alert):
        return HostContext(**self._s(alert)["host"])

    def process_tree(self, alert, depth_up=4):
        return [ProcessNode(**p) for p in self._s(alert)["tree"]]

    def network_for(self, alert, pids):
        return [NetConn(**n) for n in self._s(alert)["netconns"] if n["pid"] in pids]

    def hash_prevalence(self, sha256, days=30):
        return int(self.data["prevalence"].get(sha256, 0))

    def _contain(self, device_id):
        return {"mock": True, "contained": device_id}


def get_adapter(vendor: str, *, mock_file: Path | None = None, **kw) -> EDRAdapter:
    """Factory. With mock_file, returns the offline MockEDR for any vendor."""
    if mock_file:
        return MockEDR(vendor, mock_file, **kw)
    if vendor == "crowdstrike":
        from .crowdstrike import CrowdStrikeAdapter
        return CrowdStrikeAdapter.from_env(**kw)
    if vendor == "sentinelone":
        from .sentinelone import SentinelOneAdapter
        return SentinelOneAdapter.from_env(**kw)
    if vendor == "carbonblack":
        from .carbonblack import CarbonBlackAdapter
        return CarbonBlackAdapter.from_env(**kw)
    if vendor == "defender":
        from .defender import DefenderAdapter
        return DefenderAdapter.from_env(**kw)
    raise ValueError(f"unknown EDR vendor {vendor}")
