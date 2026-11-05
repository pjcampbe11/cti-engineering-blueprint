"""
cti-fabric - stitching a TIP, a SIEM and EDR platforms together for CTI work.

The problem this package addresses
----------------------------------
In a bank you cannot afford to index every EDR field into Splunk. A typical
EDR alert lands in the SIEM as a thin record: host, user, a hash, a process
ID, an alert name, a vendor alert ID. That is enough to route the alert, but
not enough to decide whether it is an attacker or an admin with sloppy habits.

The fix is a pivot layer: when a thin alert arrives, code calls back into the
EDR's own API (where the full telemetry already lives and is already paid
for), pulls the process tree, command lines, network connections and hash
prevalence, checks the TIP for anything known-bad, adds asset/identity
context, and only then makes a fidelity decision.

Modules
-------
  common.py      HTTP with retry, token-bucket rate limiting, audit log, data model
  edr/           one adapter per EDR behind a single interface
                 crowdstrike.py (FalconPy), sentinelone.py (Mgmt API + SDL PowerQuery),
                 carbonblack.py (CBC SDK), defender.py (Graph runHuntingQuery)
  tip.py         ThreatStream observable lookups (and an offline lookup table)
  context.py     asset / identity / change-window context (CMDB, IAM exports)
  fidelity.py    multi-signal scoring: weak signals + context -> decision
  pivot.py       orchestrates: thin alert -> EDR deep-dive -> TIP -> context -> verdict
  writeback.py   send verdicts back to Splunk (HEC) for the analyst queue / RBA
  field_budget.py  decide which EDR fields are worth indexing vs pivot-on-demand
  health.py      connector health checks (auth, lag, last data seen)
"""

__version__ = "1.0.0"
