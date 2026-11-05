"""
splunk.py - deliver intelligence into Splunk.

Three delivery patterns, in order of how often you will use them:

1. Lookup CSV (threat intel lookup)
   Write cti_threat_intel_lookup.csv and reference it from searches with
   `| lookup cti_threat_intel_lookup indicator AS dest_ip OUTPUT score tags`.
   Simple, fast, version-controllable. For Enterprise Security, the same rows
   can be loaded into the ES threat intelligence framework (ip_intel for IPs
   and domains, http_intel for URLs, file_intel for hashes, email_intel) so ES
   threat-activity correlation fires automatically.

2. HTTP Event Collector (HEC)
   POST https://<splunk>:8088/services/collector/event
   Authorization: Splunk <token>
   Send each scored observable as an event to an `cti` index. This gives a
   searchable history: when did we first know about this IOC, what score did
   it have then? That history answers "was it in the TIP before the
   incident?" - a question IR and audit will ask.

3. Anomali's own Splunk integration (ThreatStream app / Integrator)
   For volume IOC matching, prefer the vendor integration and keep custom code
   for what the vendor app does not do (hypothesis context, custom scoring,
   Sigma-derived searches).

All network writes default to dry-run.
"""

from __future__ import annotations

import csv
import json
import logging
import os
from pathlib import Path

from . import http
from .models import Observable

log = logging.getLogger("ctikit.splunk")

LOOKUP_FIELDS = ["indicator", "type", "score", "priority", "action", "tags",
                 "malware_family", "threat_actor", "attack_techniques",
                 "sources", "first_seen", "expires", "tlp", "hypothesis"]


def write_lookup(observables: list[Observable], path: Path, hypothesis_id: str) -> int:
    rows = 0
    with path.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=LOOKUP_FIELDS)
        w.writeheader()
        for o in observables:
            if o.action == "drop" or o.status == "expired":
                continue  # lookups carry only live, actionable intel
            w.writerow({
                "indicator": o.value, "type": o.type, "score": o.score,
                "priority": o.priority, "action": o.action,
                "tags": "|".join(o.tags), "malware_family": o.malware_family or "",
                "threat_actor": o.threat_actor or "",
                "attack_techniques": "|".join(o.attack_techniques),
                "sources": "|".join(o.sources), "first_seen": o.first_seen or "",
                "expires": o.expires or "", "tlp": o.tlp, "hypothesis": hypothesis_id})
            rows += 1
    return rows


def hec_events(observables: list[Observable], hypothesis_id: str) -> list[dict]:
    return [{"sourcetype": "ctikit:observable", "source": "ctikit", "index": "cti",
             "event": {**o.to_dict(), "hypothesis": hypothesis_id}} for o in observables]


def send_hec(events: list[dict], dry_run: bool = True, out_dir: Path | None = None) -> dict:
    if dry_run:
        p = (out_dir or Path(".")) / "splunk_hec_events.jsonl"
        p.write_text("\n".join(json.dumps(e) for e in events))
        return {"dry_run": True, "path": str(p), "events": len(events)}
    url = os.environ["SPLUNK_HEC_URL"].rstrip("/") + "/services/collector/event"
    # HEC accepts several JSON events concatenated in one body.
    body = "".join(json.dumps(e) for e in events).encode()
    return http.request("POST", url, headers={
        "Authorization": f"Splunk {os.environ['SPLUNK_HEC_TOKEN']}",
        "Content-Type": "application/json"}, body=body)
