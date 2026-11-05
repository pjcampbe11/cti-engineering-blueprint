"""
writeback.py - put the verdict back where analysts work (Splunk).

Design choice: write to a dedicated `cti_pivot` index via HTTP Event Collector,
and let an ES detection read that index and create findings / intermediate
findings with risk modifiers. Splunk ES keeps ownership of risk and queueing
logic (one place to tune thresholds), and the pivot service stays a data
producer that can be replaced without touching SOC workflow.

The event is compact on purpose: verdict, score, tactics, signal names and
details, top observables, errors - plus the alert ID so the ES drill-down can
open the vendor console. Full evidence stays in the EDR and in a JSON
artifact attached to the case if needed.

HEC: POST https://<splunk>:8088/services/collector/event
     Authorization: Splunk <token>
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .common import Evidence, http_json
from .fidelity import Verdict


def build_event(ev: Evidence, v: Verdict) -> dict:
    a = ev.alert
    return {
        "sourcetype": "cti:pivot:verdict", "source": "cti-fabric", "index": "cti_pivot",
        "event": {
            "alert_id": a.alert_id, "vendor": a.vendor, "alert_name": a.name,
            "host": a.host, "user": a.user, "device_id": a.device_id,
            "decision": v.decision, "score": v.score, "tactics": v.tactics,
            "signals": [{"name": s.name, "weight": s.weight, "tactic": s.tactic, "hard": s.hard,
                         "detail": s.detail} for s in v.signals],
            "modifiers": v.modifiers, "reason": v.reason,
            "tip_hits": ev.tip_hits[:10],
            "process_chain": " > ".join(n.name for n in ev.tree[:8]),
            "remote_ips": sorted({n.remote_ip for n in ev.netconns if n.remote_ip})[:20],
            "domains": sorted({n.domain for n in ev.netconns if n.domain})[:20],
            "rare_hashes": [h for h, c in ev.hash_prevalence.items() if c <= 2],
            "pivot_errors": ev.errors,
            # risk fields so an ES detection can map them straight to a risk modifier
            "risk_object": a.host, "risk_object_type": "system", "risk_score": v.score,
        },
    }


def send(events: list[dict], dry_run: bool = True, out: Path | None = None) -> dict:
    if dry_run:
        p = out or Path("pivot_verdicts.jsonl")
        p.write_text("\n".join(json.dumps(e) for e in events) + "\n")
        return {"dry_run": True, "path": str(p), "events": len(events)}
    url = os.environ["SPLUNK_HEC_URL"].rstrip("/") + "/services/collector/event"
    return http_json("POST", url, headers={"Authorization": f"Splunk {os.environ['SPLUNK_HEC_TOKEN']}"},
                     body="".join(json.dumps(e) for e in events).encode(), purpose="hec-writeback")
