"""
coverage.py - find the systems nobody is watching.

Every intelligence product assumes telemetry exists. In a large enterprise the
real picture is: most Windows endpoints have EDR; many Linux servers, cloud
workloads, appliances, legacy and OT systems do not - because the OS or kernel
is unsupported, the vendor forbids agents (appliances), performance or change
policies block it, or the asset is simply unknown.

This module reconciles inventories to classify every asset:

  EDR_HEALTHY    EDR agent present and checked in recently
  EDR_STALE      agent present but silent > stale_days (broken, offline, decommissioned?)
  SENSOR_ONLY    no EDR, but a runtime sensor (e.g. Wiz Runtime Sensor) covers it
  LOGS_ONLY      no agent; host logs reach the SIEM (Sysmon / auditd / osquery / syslog)
  BLIND          nothing - the gap list
  UNMANAGED      seen by EDR or logs but NOT in the CMDB (shadow IT / unknown asset)

Then it recommends a compensating control per platform, so the output is a
work plan, not just a scary number. Inputs are CSV exports (CMDB, EDR consoles,
Wiz inventory, Splunk `| tstats` of hosts per sourcetype) - see mocks/coverage/.
"""

from __future__ import annotations

import csv
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

RECOMMEND = {
    "windows": "Deploy EDR; if blocked, native/standalone Sysmon with the repo config + Windows Event Forwarding",
    "linux": "EDR Linux sensor if the kernel is supported; else an eBPF runtime sensor (e.g. Wiz Runtime Sensor) or Sysmon for Linux on modern kernels; on old kernels without usable eBPF (e.g. RHEL 6) use auditd + osquery to the SIEM",
    "container": "Runtime sensor as a Kubernetes DaemonSet (e.g. Wiz Runtime Sensor) + k8s audit logs",
    "appliance": "Vendor syslog + config backup diffing + NetFlow/NDR around it; agents usually unsupported",
    "mainframe": "SMF / RACF (or ACF2/Top Secret) events forwarded via syslog connector",
    "ot": "Passive network monitoring (OT NDR) at the segment boundary; never active agents without OT approval",
    "unknown": "Identify owner and platform first - an unknown asset is itself the finding",
}


def _read(p: Path) -> list[dict]:
    if not Path(p).exists():
        return []
    with Path(p).open() as fh:
        return list(csv.DictReader(fh))


def _age_days(iso: str | None, now: datetime) -> float:
    if not iso:
        return 1e9
    return (now - datetime.fromisoformat(iso.replace("Z", "+00:00"))).total_seconds() / 86400


def reconcile(folder: Path, stale_days: int = 7, now: datetime | None = None) -> dict:
    folder = Path(folder)
    now = now or datetime.now(timezone.utc)
    cmdb = {r["hostname"].lower(): r for r in _read(folder / "cmdb.csv")}
    edr = {r["hostname"].lower(): r for r in _read(folder / "edr_agents.csv")}
    sensor = {r["hostname"].lower(): r for r in _read(folder / "runtime_sensors.csv")}
    logs: dict[str, set] = {}
    for r in _read(folder / "siem_log_sources.csv"):
        if _age_days(r.get("last_event"), now) <= stale_days:
            logs.setdefault(r["hostname"].lower(), set()).add(r["sourcetype"])

    rows = []
    for h in sorted(set(cmdb) | set(edr) | set(sensor) | set(logs)):
        c = cmdb.get(h)
        plat = (c or {}).get("platform", "unknown").lower()
        if not c:
            cls = "UNMANAGED"
        elif h in edr and _age_days(edr[h].get("last_seen"), now) <= stale_days:
            cls = "EDR_HEALTHY"
        elif h in edr:
            cls = "EDR_STALE"
        elif h in sensor:
            cls = "SENSOR_ONLY"
        elif h in logs:
            cls = "LOGS_ONLY"
        else:
            cls = "BLIND"
        rows.append({"hostname": h, "platform": plat, "criticality": int((c or {}).get("criticality") or 0),
                     "owner": (c or {}).get("owner", ""), "class": cls,
                     "edr_vendor": edr.get(h, {}).get("vendor", ""),
                     "log_sources": ",".join(sorted(logs.get(h, []))),
                     "recommendation": "" if cls == "EDR_HEALTHY" else
                     ("Investigate agent health / decommission status" if cls == "EDR_STALE"
                      else RECOMMEND.get(plat, RECOMMEND["unknown"]))})
    by = Counter(r["class"] for r in rows)
    crit_gaps = [r for r in rows if r["class"] in ("BLIND", "EDR_STALE", "UNMANAGED") and r["criticality"] >= 4]
    managed = [r for r in rows if r["class"] != "UNMANAGED"]
    return {"assets": len(managed), "by_class": dict(by),
            "edr_coverage_pct": round(100 * by.get("EDR_HEALTHY", 0) / (len(managed) or 1), 1),
            "any_telemetry_pct": round(100 * sum(by.get(k, 0) for k in
                                                ("EDR_HEALTHY", "SENSOR_ONLY", "LOGS_ONLY")) / (len(managed) or 1), 1),
            "critical_gaps": crit_gaps, "rows": rows}


def write_csv(rows: list[dict], path: Path) -> None:
    with Path(path).open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
