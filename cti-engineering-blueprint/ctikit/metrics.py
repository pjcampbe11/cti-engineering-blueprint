"""
metrics.py - Feedback phase: measure the pipeline and the program.

Two kinds of metrics, and you should name both in the interview:

Pipeline health (engineering metrics - this module computes them per run)
  * collected per feed / feed errors          -> is every source alive?
  * dedupe ratio, corroboration rate          -> how much feed overlap are we paying for?
  * relevance rate                            -> how much of the firehose answered the question?
  * action distribution (block/detect/hunt/drop)
  * coverage % for the hypothesis TTPs
  * Sigma conversion errors, STIX validity    -> CI gates
  * run duration

Program value (tracked over time in Splunk from the HEC events + ticketing)
  * time from intel receipt -> indicator live in controls (mean time to operationalize)
  * % of SOC alerts enriched by CTI; true-positive rate of CTI-sourced alerts
  * detections created / tuned from CTI per quarter; ATT&CK coverage trend
  * intel requirements (PIRs) answered vs open; stakeholder feedback scores
  * incidents where CTI shortened scoping (IR feedback)
"""

from __future__ import annotations

from collections import Counter


def compute(raw_count: int, observables, feed_stats: dict, rows, sigma_res: dict,
            stix_ok: bool, duration_s: float) -> dict:
    n = len(observables) or 1
    actions = Counter(o.action for o in observables)
    relevant = [o for o in observables if "hypothesis-relevant" in o.tags]
    covered = sum(1 for r in rows if r["state"] == "covered")
    return {
        "raw_observables_collected": raw_count,
        "unique_after_dedupe": len(observables),
        "dedupe_ratio": round(1 - len(observables) / raw_count, 3) if raw_count else 0,
        "corroborated_multi_source": sum(1 for o in observables if len(o.sources) > 1),
        "hypothesis_relevant": len(relevant),
        "relevance_rate": round(len(relevant) / n, 3),
        "action_block": actions.get("block", 0),
        "action_detect": actions.get("detect", 0),
        "action_hunt": actions.get("hunt", 0),
        "action_drop": actions.get("drop", 0),
        "expired": sum(1 for o in observables if o.status == "expired"),
        "ttp_coverage_pct": round(100 * covered / (len(rows) or 1)),
        "sigma_rules_converted": sigma_res.get("converted", 0),
        "sigma_errors": len(sigma_res.get("errors", [])),
        "stix_bundle_valid": stix_ok,
        "feeds_ok": sum(1 for v in feed_stats.values() if v["status"] == "ok"),
        "feeds_failed": sum(1 for v in feed_stats.values() if v["status"] != "ok"),
        "run_seconds": round(duration_s, 2),
        "feed_detail": feed_stats,
    }
