#!/usr/bin/env python3
"""
cti.py - command line entry point for the CTI lifecycle toolkit.

Examples
--------
  # Full lifecycle against bundled synthetic data (no keys needed):
  python cti.py run hypotheses/HYP-2026-001-helpdesk-idp-takeover.yaml --offline

  # Same, live feeds (needs env vars - see config/env.example), still dry-run:
  python cti.py run hypotheses/HYP-2026-001-helpdesk-idp-takeover.yaml

  # Live AND push to ThreatStream + Splunk HEC (change-controlled use only):
  python cti.py run hypotheses/HYP-2026-001-helpdesk-idp-takeover.yaml --push

  # CI gate: hypotheses, Sigma and YARA must all parse/convert/compile:
  python cti.py validate
"""

import argparse
import json
import logging
import sys

from ctikit import pipeline


def main() -> int:
    ap = argparse.ArgumentParser(description="CTI lifecycle toolkit")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run one hypothesis through the full lifecycle")
    r.add_argument("hypothesis")
    r.add_argument("--offline", action="store_true", help="use bundled synthetic sample data")
    r.add_argument("--push", action="store_true", help="actually write to ThreatStream / Splunk HEC")
    sub.add_parser("validate", help="CI checks for hypotheses, Sigma, YARA")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    if a.cmd == "run":
        if a.push and a.offline:
            ap.error("--push makes no sense with --offline sample data")
        res = pipeline.run(a.hypothesis, offline=a.offline, push=a.push)
        m = {k: v for k, v in res["metrics"].items() if k != "feed_detail"}
        print(json.dumps({"out_dir": res["out_dir"], "metrics": m}, indent=2))
        return 0
    res = pipeline.validate_repo()
    print(json.dumps(res, indent=2))
    return 1 if res["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
