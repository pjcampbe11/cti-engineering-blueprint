"""
pivot.py - the orchestration: thin SIEM alert -> deep EDR evidence -> verdict.

Sequence (each step tolerates failure of the others and records it):
  1. enrich_alert   fill missing IDs from the vendor's full alert record
  2. host_context   EDR's view of the device
  3. process_tree   ancestors + target + children (vendor-native keys)
  4. network_for    connections and DNS for every process in the tree
  5. prevalence     how rare is each binary in the fleet?
  6. TIP lookup     every IP, domain and hash collected above
  7. context        asset / identity / change window
  8. fidelity       signals + context -> escalate | review | suppress
  9. write-back     verdict + evidence summary to Splunk (HEC)

Time budget: an analyst is waiting. Default budget is 90 seconds; slow steps
(prevalence over 30 days) are skipped when the budget runs out, and the
verdict records what was skipped. Partial evidence with an honest gap list is
better than a timeout.
"""

from __future__ import annotations

import logging
import time

from .common import Evidence, ThinAlert
from . import fidelity

log = logging.getLogger("fabric.pivot")


def run(alert: ThinAlert, edr, tip=None, context=None, budget_s: float = 90.0) -> tuple[Evidence, fidelity.Verdict]:
    t0 = time.monotonic()
    ev = Evidence(alert=alert)

    def left() -> float:
        return budget_s - (time.monotonic() - t0)

    def step(name, fn):
        if left() <= 0:
            ev.errors.append(f"{name}: skipped (time budget)")
            return None
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - partial evidence beats no evidence
            ev.errors.append(f"{name}: {type(e).__name__}: {e}")
            log.warning("pivot step %s failed: %s", name, e)
            return None

    if hasattr(edr, "enrich_alert"):
        step("enrich_alert", lambda: edr.enrich_alert(alert))
    ev.host = step("host_context", lambda: edr.host_context(alert))
    ev.tree = step("process_tree", lambda: edr.process_tree(alert)) or []
    pids = [n.pid for n in ev.tree if n.pid]
    ev.netconns = step("network", lambda: edr.network_for(alert, pids)) or []

    for sha in {n.sha256 for n in ev.tree if n.sha256}:
        v = step(f"prevalence:{sha[:12]}", lambda s=sha: edr.hash_prevalence(s))
        if v is not None:
            ev.hash_prevalence[sha] = v

    if tip:
        observables = [n.remote_ip for n in ev.netconns] + [n.domain for n in ev.netconns if n.domain] + \
                      [n.sha256 for n in ev.tree if n.sha256]
        ev.tip_hits = step("tip_lookup", lambda: tip.lookup(observables)) or []
    if context:
        ev.context = step("context", lambda: context.for_alert(alert.host, alert.user, alert.timestamp)) or {}

    verdict = fidelity.decide(ev)
    log.info("pivot %s -> %s (score %d, %.1fs, %d errors)", alert.alert_id, verdict.decision,
             verdict.score, time.monotonic() - t0, len(ev.errors))
    return ev, verdict
