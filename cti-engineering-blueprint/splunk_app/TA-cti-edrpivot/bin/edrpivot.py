#!/usr/bin/env python3
"""
edrpivot.py - Splunk custom streaming search command.

    index=notable OR index=edr_alerts vendor=*
    | edrpivot vendor_field=vendor alert_field=alert_id host_field=host user_field=user
               device_field=device_id process_field=process_id
    | table _time host user pivot_decision pivot_score pivot_tactics pivot_signals pivot_reason

Why a search command: analysts and ES detections can call the pivot inline,
and the same code backs SOAR playbooks and the scheduled pivot service. One
pivot implementation, three entry points.

Packaging:
  * Copy the repo's `fabric/` package into this app's bin/ (or lib/ on sys.path).
  * Vendor splunklib (splunk-sdk) into bin/ - Splunk does not ship it for apps.
  * Credentials: store in Splunk's storage/passwords (encrypted) and read them
    with self.service.storage_passwords, never in .conf files. This example
    reads environment variables to stay short.
  * Guard rails: `maxrows` caps how many rows one search can pivot, so a broad
    search cannot hammer EDR API quotas.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators  # noqa: E402

from fabric.common import ThinAlert  # noqa: E402
from fabric.edr import get_adapter  # noqa: E402
from fabric import pivot  # noqa: E402


@Configuration()
class EdrPivotCommand(StreamingCommand):
    vendor_field = Option(require=False, default="vendor")
    alert_field = Option(require=False, default="alert_id")
    host_field = Option(require=False, default="host")
    user_field = Option(require=False, default="user")
    device_field = Option(require=False, default="device_id")
    process_field = Option(require=False, default="process_id")
    maxrows = Option(require=False, default=25, validate=validators.Integer(minimum=1, maximum=500))
    budget = Option(require=False, default=60, validate=validators.Integer(minimum=5, maximum=300))

    def stream(self, records):
        adapters, n = {}, 0
        for rec in records:
            n += 1
            if n > self.maxrows:
                rec["pivot_decision"] = "skipped_maxrows"
                yield rec
                continue
            vendor = rec.get(self.vendor_field)
            try:
                if vendor not in adapters:
                    adapters[vendor] = get_adapter(vendor)
                alert = ThinAlert(alert_id=rec.get(self.alert_field, ""), vendor=vendor, name=rec.get("name", ""),
                                  host=rec.get(self.host_field, ""), user=rec.get(self.user_field),
                                  device_id=rec.get(self.device_field), process_id=rec.get(self.process_field))
                ev, v = pivot.run(alert, adapters[vendor], budget_s=float(self.budget))
                rec.update({"pivot_decision": v.decision, "pivot_score": v.score,
                            "pivot_tactics": v.tactics, "pivot_signals": [s.name for s in v.signals],
                            "pivot_reason": v.reason, "pivot_chain": " > ".join(x.name for x in ev.tree[:8]),
                            "pivot_errors": ev.errors})
            except Exception as e:  # noqa: BLE001 - never break the search
                rec["pivot_decision"] = "error"
                rec["pivot_errors"] = str(e)[:300]
            yield rec


dispatch(EdrPivotCommand, sys.argv, sys.stdin, sys.stdout, __name__)
