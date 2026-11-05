"""
field_budget.py - decide which EDR fields earn a place in the SIEM.

Splunk is licensed by ingest volume (or by workload/compute, depending on
contract), so every field you forward from the EDR has a recurring cost. The
question is not "is this field useful?" (they all are, sometime) but "does this
field need to be searchable in the SIEM at alert time, or can we fetch it from
the EDR on demand?"

Method
  1. Take a sample of raw EDR events (JSONL) as they would be forwarded.
  2. Measure each field: fill rate, average bytes, distinct values.
  3. Parse the detection content you actually run (SPL / Sigma / KQL files)
     and record which fields detections reference.
  4. Classify:
       INDEX  - referenced by a detection, OR a routing/pivot key
                (host, user, device ID, process key, hash, timestamp, alert ID)
       PIVOT  - not referenced; stays in the EDR, fetched by the pivot layer
       DROP   - near-empty or pure noise (fill rate < 1%)
  5. Project GB/day for "everything" vs "INDEX only" at your event volume.

This turns a cost argument into an engineering decision with numbers, and the
output doubles as the field allowlist for your forwarder / pipeline tool
(Splunk Ingest Actions or Edge Processor, Cribl, a Logstash filter, or the
EDR's own streaming export filter).
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

# Fields we always keep: without these the pivot layer has nothing to pivot on.
PIVOT_KEYS = {"timestamp", "@timestamp", "_time", "aid", "device_id", "hostname", "host", "computername",
              "user", "username", "user_name", "alert_id", "detection_id", "targetprocessid",
              "process_guid", "storyline_id", "sha256", "sha256hashdata", "event_simplename", "event_type"}


def flatten(d: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(flatten(v, key + "."))
        else:
            out[key] = v
    return out


def referenced_fields(detection_dir: Path) -> set[str]:
    """Crude but effective: any token in detection files that matches a field
    name in the sample counts as referenced. Over-inclusion is safe here."""
    tokens = set()
    for p in Path(detection_dir).rglob("*"):
        if p.suffix.lower() in {".spl", ".yml", ".yaml", ".kql", ".conf", ".txt"}:
            tokens |= {t.lower() for t in re.findall(r"[A-Za-z_][A-Za-z0-9_.{}]*", p.read_text(errors="ignore"))}
    return tokens


def analyze(sample_jsonl: Path, detection_dir: Path, events_per_day: int) -> dict:
    stats = defaultdict(lambda: {"present": 0, "bytes": 0, "values": set()})
    n = 0
    for line in Path(sample_jsonl).read_text().splitlines():
        if not line.strip():
            continue
        n += 1
        for k, v in flatten(json.loads(line)).items():
            s = stats[k]
            s["present"] += 1
            sv = json.dumps(v) if not isinstance(v, str) else v
            s["bytes"] += len(k) + len(sv) + 4      # key + value + JSON overhead
            if len(s["values"]) < 5000:
                s["values"].add(sv[:200])
    refs = referenced_fields(detection_dir)
    rows, total_b, keep_b = [], 0.0, 0.0
    for k, s in stats.items():
        fill = s["present"] / n
        avg_b = s["bytes"] / n                        # bytes per event (averaged over all events)
        leaf = k.split(".")[-1].lower()
        used = k.lower() in refs or leaf in refs
        if leaf in PIVOT_KEYS or k.lower() in PIVOT_KEYS:
            cls, why = "INDEX", "pivot/routing key"
        elif used:
            cls, why = "INDEX", "referenced by a detection"
        elif fill < 0.01:
            cls, why = "DROP", "fill rate < 1%"
        else:
            cls, why = "PIVOT", "not used by detections - fetch from EDR on demand"
        total_b += avg_b
        keep_b += avg_b if cls == "INDEX" else 0
        rows.append({"field": k, "class": cls, "why": why, "fill_rate": round(fill, 3),
                     "avg_bytes_per_event": round(avg_b, 1), "distinct_sampled": len(s["values"])})
    gb = lambda b: round(b * events_per_day / 1024 ** 3, 2)  # noqa: E731
    rows.sort(key=lambda r: (r["class"], -r["avg_bytes_per_event"]))
    return {"sampled_events": n, "events_per_day": events_per_day,
            "gb_per_day_all_fields": gb(total_b), "gb_per_day_index_only": gb(keep_b),
            "reduction_pct": round(100 * (1 - keep_b / total_b), 1) if total_b else 0,
            "index_allowlist": sorted(r["field"] for r in rows if r["class"] == "INDEX"),
            "fields": rows}
