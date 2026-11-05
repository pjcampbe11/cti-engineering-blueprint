#!/usr/bin/env python3
"""
fabric_cli.py - command line for the integration layer.

  # Pivot three identical-looking thin alerts against mock EDR data and see
  # why one escalates, one is suppressed and one goes to review:
  python fabric_cli.py pivot --mock

  # Live: pivot one alert against a real EDR (env vars per adapter, see config/env.example)
  python fabric_cli.py pivot --alert alert.json --edr crowdstrike --tip threatstream

  # Which EDR fields are worth indexing in the SIEM?
  python fabric_cli.py field-budget --sample mocks/field_budget_sample.jsonl \
      --detections mocks/field_budget_detections --events-per-day 2000000000

  # Who has no EDR / no telemetry at all?
  python fabric_cli.py coverage --inventory mocks/coverage

  # Pull Wiz Defend runtime sensor detections into the same pipeline
  python fabric_cli.py wiz-pull --since 2026-11-05T00:00:00Z
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from fabric import coverage, field_budget, pivot, writeback
from fabric.common import ThinAlert
from fabric.context import Context
from fabric.edr import get_adapter
from fabric.tip import CsvTIP, ThreatStreamTIP

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "out"


def cmd_pivot(a):
    OUT.mkdir(exist_ok=True)
    if a.mock:
        alerts = [ThinAlert(**x) for x in json.loads((ROOT / "mocks/thin_alerts.json").read_text())]
        tip = CsvTIP(ROOT / "mocks/tip_lookup.csv")
        ctx = Context(ROOT / "mocks/context")
    else:
        alerts = [ThinAlert(**json.loads(Path(a.alert).read_text()))]
        tip = ThreatStreamTIP.from_env() if a.tip == "threatstream" else (CsvTIP(Path(a.tip)) if a.tip else None)
        ctx = Context(Path(a.context)) if a.context else None
    events, summary = [], []
    for al in alerts:
        edr = get_adapter(a.edr or al.vendor, mock_file=(ROOT / "mocks/scenarios.json") if a.mock else None)
        ev, v = pivot.run(al, edr, tip, ctx, budget_s=a.budget)
        events.append(writeback.build_event(ev, v))
        summary.append({"alert": al.alert_id, "host": al.host, "user": al.user, "decision": v.decision,
                        "score": v.score, "tactics": v.tactics,
                        "signals": [f"{s.name}({s.weight}{',HARD' if s.hard else ''})" for s in v.signals],
                        "modifiers": v.modifiers, "reason": v.reason, "errors": ev.errors})
    res = writeback.send(events, dry_run=not a.push, out=OUT / "pivot_verdicts.jsonl")
    (OUT / "pivot_summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps({"writeback": res, "verdicts": summary}, indent=2))


def cmd_budget(a):
    OUT.mkdir(exist_ok=True)
    r = field_budget.analyze(Path(a.sample), Path(a.detections), a.events_per_day)
    (OUT / "field_budget.json").write_text(json.dumps(r, indent=2))
    print(json.dumps({k: v for k, v in r.items() if k != "fields"}, indent=2))
    for f in r["fields"]:
        print(f"  {f['class']:6} {f['field']:28} fill={f['fill_rate']:<5} bytes/evt={f['avg_bytes_per_event']:<7} {f['why']}")


def cmd_coverage(a):
    OUT.mkdir(exist_ok=True)
    now = datetime.fromisoformat(a.now.replace("Z", "+00:00")) if a.now else None
    r = coverage.reconcile(Path(a.inventory), stale_days=a.stale_days, now=now)
    coverage.write_csv(r["rows"], OUT / "coverage_report.csv")
    print(json.dumps({k: v for k, v in r.items() if k != "rows"}, indent=2))


def cmd_wiz(a):
    from fabric.wiz import WizClient, detection_to_alert
    c = WizClient.from_env()
    alerts = [detection_to_alert(d).__dict__ for d in c.sensor_detections(a.since)]
    OUT.mkdir(exist_ok=True)
    (OUT / "wiz_alerts.json").write_text(json.dumps(alerts, indent=2, default=str))
    print(f"{len(alerts)} Wiz sensor detections normalized -> out/wiz_alerts.json")


def main():
    ap = argparse.ArgumentParser(description="cti-fabric integration layer")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("pivot")
    p.add_argument("--mock", action="store_true")
    p.add_argument("--alert"), p.add_argument("--edr"), p.add_argument("--tip"), p.add_argument("--context")
    p.add_argument("--budget", type=float, default=90.0)
    p.add_argument("--push", action="store_true", help="send verdicts to Splunk HEC")
    b = sub.add_parser("field-budget")
    b.add_argument("--sample", required=True), b.add_argument("--detections", required=True)
    b.add_argument("--events-per-day", type=int, default=1_000_000_000)
    c = sub.add_parser("coverage")
    c.add_argument("--inventory", required=True), c.add_argument("--stale-days", type=int, default=7)
    c.add_argument("--now", help="ISO time to evaluate against (for reproducible demos)")
    w = sub.add_parser("wiz-pull")
    w.add_argument("--since", required=True)
    a = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    {"pivot": cmd_pivot, "field-budget": cmd_budget, "coverage": cmd_coverage, "wiz-pull": cmd_wiz}[a.cmd](a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
