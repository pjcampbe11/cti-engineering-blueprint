"""
common.py - shared plumbing: data model, HTTP, rate limiting, audit trail.

Design rules every adapter follows (worth saying out loud in an interview):
  1. Read-only by default. Response actions (isolate, kill, ban hash) exist in
     the interface but refuse to run unless `allow_response=True` AND an
     approval reference is supplied. In a bank, containment is a change with
     an owner, not something a script does on its own.
  2. Every outbound call is audit-logged (who/what/why, never the secret).
  3. Every vendor has a rate limit; we enforce our own budget below theirs so
     a busy alert day does not lock the SOC out of the console.
  4. Vendor-specific shapes never leave the adapter. Everything returns the
     normalized dataclasses below, so pivot.py and fidelity.py are vendor-blind.
"""

from __future__ import annotations

import json
import logging
import os
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

log = logging.getLogger("fabric")
audit_log = logging.getLogger("fabric.audit")


# ---------------------------------------------------------------------------
# Normalized data model
# ---------------------------------------------------------------------------
@dataclass
class ThinAlert:
    """What typically reaches the SIEM: a handful of extracted fields.

    This is deliberately small. The whole point of the pivot layer is that
    the SIEM does not need to carry everything.
    """
    alert_id: str
    vendor: str                      # crowdstrike | sentinelone | carbonblack | defender
    name: str
    host: str
    user: Optional[str] = None
    device_id: Optional[str] = None  # vendor agent/device ID if the alert carries it
    process_id: Optional[str] = None # vendor process key (CS TargetProcessId, CB process_guid, ...)
    sha256: Optional[str] = None
    cmdline: Optional[str] = None
    severity: Optional[int] = None
    tactic: Optional[str] = None     # ATT&CK tactic from the vendor, if present
    technique: Optional[str] = None
    timestamp: Optional[str] = None
    raw: dict = field(default_factory=dict)


@dataclass
class ProcessNode:
    pid: str                          # vendor process key, not just the OS PID
    name: str
    cmdline: str = ""
    sha256: Optional[str] = None
    user: Optional[str] = None
    parent_pid: Optional[str] = None
    signed: Optional[bool] = None
    start_time: Optional[str] = None


@dataclass
class NetConn:
    pid: str
    remote_ip: str
    remote_port: Optional[int] = None
    domain: Optional[str] = None
    direction: str = "outbound"


@dataclass
class HostContext:
    device_id: str
    hostname: str
    os: Optional[str] = None
    last_seen: Optional[str] = None
    ou_or_group: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    external_ip: Optional[str] = None


@dataclass
class Evidence:
    """Everything the pivot pulled for one alert."""
    alert: ThinAlert
    host: Optional[HostContext] = None
    tree: list[ProcessNode] = field(default_factory=list)       # ancestors + target + children
    netconns: list[NetConn] = field(default_factory=list)
    hash_prevalence: dict[str, int] = field(default_factory=dict)  # sha256 -> # hosts seen on
    tip_hits: list[dict] = field(default_factory=list)
    context: dict = field(default_factory=dict)                 # asset/identity/change-window
    errors: list[str] = field(default_factory=list)             # partial-failure record

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Rate limiting - token bucket per vendor
# ---------------------------------------------------------------------------
class TokenBucket:
    """Simple thread-safe token bucket.

    Example budgets (set yours BELOW the vendor's published limit so humans in
    the console keep headroom):
      Microsoft Graph runHuntingQuery: vendor allows 45 calls/min -> we use 30
      CrowdStrike: per-CID limits vary by endpoint -> read X-RateLimit-Remaining
    """

    def __init__(self, rate_per_min: float, burst: int | None = None):
        self.capacity = burst or max(1, int(rate_per_min))
        self.tokens = float(self.capacity)
        self.fill_rate = rate_per_min / 60.0
        self.ts = time.monotonic()
        self.lock = threading.Lock()

    def take(self) -> None:
        with self.lock:
            while True:
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now - self.ts) * self.fill_rate)
                self.ts = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                time.sleep((1 - self.tokens) / self.fill_rate)


# ---------------------------------------------------------------------------
# HTTP helper (stdlib only, so it runs on a locked-down integration host)
# ---------------------------------------------------------------------------
RETRY_STATUS = {429, 500, 502, 503, 504}


def http_json(method: str, url: str, *, headers: dict | None = None, body: Any = None,
              params: dict | None = None, retries: int = 4, timeout: int = 60,
              bucket: TokenBucket | None = None, purpose: str = "") -> Any:
    if params:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params, doseq=True)
    hdrs = {"Accept": "application/json", "User-Agent": "cti-fabric/1.0"}
    hdrs.update(headers or {})
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    ca = os.environ.get("REQUESTS_CA_BUNDLE")
    ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
    delay = 2.0
    for attempt in range(1, retries + 1):
        if bucket:
            bucket.take()
        audit(method, url, purpose)
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                raw = r.read().decode("utf-8", "replace")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            if e.code in RETRY_STATUS and attempt < retries:
                time.sleep(float(e.headers.get("Retry-After") or delay))
                delay *= 2
                continue
            raise
        except urllib.error.URLError:
            if attempt < retries:
                time.sleep(delay)
                delay *= 2
                continue
            raise


def audit(action: str, target: str, purpose: str) -> None:
    """Write an audit line. Strip query strings - some APIs put keys there."""
    target = target.split("?")[0]
    audit_log.info(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                               "action": action, "target": target, "purpose": purpose,
                               "actor": os.environ.get("FABRIC_SERVICE_ACCOUNT", "cti-fabric")}))


class ResponseActionBlocked(PermissionError):
    """Raised when someone tries a containment action without approval."""


def require_approval(allow_response: bool, approval_ref: str | None, action: str) -> None:
    if not allow_response or not approval_ref:
        raise ResponseActionBlocked(
            f"{action} refused: response actions need allow_response=True and an approval/ticket reference")
    audit("RESPONSE", action, f"approved by {approval_ref}")
