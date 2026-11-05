"""
wiz.py - Wiz (Wiz Defend / Runtime Sensor) connector.

Where Wiz fits in this architecture
-----------------------------------
Traditional EDR agents cover user endpoints and many servers well. They are
weaker or absent on ephemeral cloud workloads: Kubernetes nodes and pods,
short-lived containers, serverless, some Linux distributions and kernels,
appliances. Wiz covers two layers there:
  * Agentless (API/snapshot) inventory, vulnerability and posture context for
    cloud resources - useful as an INVENTORY SOURCE for coverage-gap analysis.
  * The Wiz Runtime Sensor, a lightweight eBPF sensor (Linux workloads,
    containers/Kubernetes as a DaemonSet, VMs; Windows support added in 2026),
    whose detections surface in Wiz Defend. Detections carry process trees
    and, with Wiz Forensics, a forensic package captured at detection time.

API facts (Wiz GraphQL API):
  * Auth: OAuth2 client credentials. POST https://auth.app.wiz.io/oauth/token
    with grant_type=client_credentials, client_id, client_secret, audience=wiz-api.
    (Service account created under Settings > Service Accounts, type Custom
    Integration / GraphQL API.)
  * API: https://api.<region>.app.wiz.io/graphql  (region from the console's
    user settings page; e.g. us1, us17, us20, eu1).
  * Scopes used here: read:detections, read:cloud_events_sensor, read:issues,
    read:resources (inventory).
  * Integrators poll a detections query (e.g. DetectionsTableV2) with cursor
    pagination. Wiz's schema is unversioned and evolves - export the exact
    query from the Wiz API Explorer / docs into queries/*.graphql rather than
    hard-coding it, which is what this module does.
"""

from __future__ import annotations

import os
import time
import urllib.parse
from pathlib import Path

from .common import ThinAlert, http_json, TokenBucket

QUERIES = Path(__file__).resolve().parent.parent / "queries"


class WizClient:
    def __init__(self, client_id: str, client_secret: str, api_url: str,
                 auth_url: str = "https://auth.app.wiz.io/oauth/token", audience: str = "wiz-api"):
        self.cid, self.secret, self.audience = client_id, client_secret, audience
        self.api = api_url.rstrip("/")
        if not self.api.endswith("/graphql"):
            self.api += "/graphql"
        self.auth = auth_url
        self._tok, self._exp = None, 0.0
        self.bucket = TokenBucket(rate_per_min=60)

    @classmethod
    def from_env(cls):
        return cls(os.environ["WIZ_CLIENT_ID"], os.environ["WIZ_CLIENT_SECRET"], os.environ["WIZ_API_URL"],
                   os.environ.get("WIZ_AUTH_URL", "https://auth.app.wiz.io/oauth/token"))

    def _token(self) -> str:
        if self._tok and time.time() < self._exp - 60:
            return self._tok
        form = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": self.cid,
                                       "client_secret": self.secret, "audience": self.audience}).encode()
        r = http_json("POST", self.auth, body=form,
                      headers={"Content-Type": "application/x-www-form-urlencoded"}, purpose="wiz-token")
        self._tok, self._exp = r["access_token"], time.time() + int(r.get("expires_in", 3600))
        return self._tok

    def gql(self, query: str, variables: dict | None = None) -> dict:
        r = http_json("POST", self.api, headers={"Authorization": f"Bearer {self._token()}"},
                      body={"query": query, "variables": variables or {}}, bucket=self.bucket,
                      purpose="wiz-graphql")
        if r.get("errors"):
            raise RuntimeError(f"Wiz GraphQL error: {r['errors'][:2]}")
        return r["data"]

    def paginate(self, query: str, variables: dict, root: str, max_pages: int = 50):
        """Generic cursor pagination for Wiz connection-style results
        ({nodes, pageInfo {hasNextPage endCursor}})."""
        after = None
        for _ in range(max_pages):
            data = self.gql(query, {**variables, "after": after})[root]
            for n in data.get("nodes", []):
                yield n
            pi = data.get("pageInfo") or {}
            if not pi.get("hasNextPage"):
                return
            after = pi.get("endCursor")

    def sensor_detections(self, since_iso: str):
        q = (QUERIES / "wiz_detections.graphql").read_text()
        yield from self.paginate(q, {"first": 500, "since": since_iso}, root="detections")


def detection_to_alert(d: dict) -> ThinAlert:
    """Normalize a Wiz detection node into the shared ThinAlert so the same
    fidelity scoring and write-back apply to cloud workloads."""
    res = (d.get("resources") or [{}])[0] if isinstance(d.get("resources"), list) else (d.get("resource") or {})
    proc = (d.get("triggeringEvent") or {}).get("process") or {}
    return ThinAlert(alert_id=d.get("id", ""), vendor="wiz", name=(d.get("ruleMatch") or {}).get("ruleName")
                     or d.get("description", "Wiz detection"),
                     host=res.get("name") or res.get("providerUniqueId", ""), device_id=res.get("id"),
                     sha256=proc.get("sha256"), cmdline=proc.get("commandLine"),
                     severity={"CRITICAL": 10, "HIGH": 8, "MEDIUM": 5, "LOW": 3}.get(d.get("severity"), 5),
                     tactic=(d.get("mitreTactics") or [None])[0], technique=(d.get("mitreTechniques") or [None])[0],
                     timestamp=d.get("createdAt"), raw=d)
