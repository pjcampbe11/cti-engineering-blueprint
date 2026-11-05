"""
fidelity.py - turn many weak signals plus context into one defensible decision.

The problem
-----------
"PowerShell with an encoded command" fires for attackers AND for admins and
management tools. Alerting on it alone floods the queue; suppressing it hides
real intrusions. High fidelity comes from the combination:
  behavior signals (from the EDR pivot) + intel (TIP) + rarity (prevalence)
  + entity context (who, where, change window) + tactic diversity.

This mirrors risk-based alerting (RBA) in Splunk Enterprise Security - where,
in ES 8.x terms, detections write "intermediate findings" with risk scores and
"finding-based detections" raise a "finding" when an entity's combined risk,
or the number of distinct ATT&CK tactics, crosses a threshold. The difference
here: the evidence comes from an on-demand EDR pivot rather than from data you
paid to index.

Rules of the model (keep them explainable)
  * Signals have a weight and an ATT&CK tactic.
  * HARD signals (TIP high-confidence match, credential dumping) are never
    discounted by context. An admin running Mimikatz is still an incident.
  * SOFT signals are discounted when context explains them (privileged user
    on an admin host, inside an approved change window).
  * Crown-jewel assets amplify.
  * Escalate on (score >= 70 AND >= 2 tactics) OR any hard signal.
  * 40-69 -> analyst review with the evidence package attached.
  * < 40  -> suppress as an intermediate/risk record, with the reason written down.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .common import Evidence

OFFICE = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "onenote.exe"}
SCRIPT_HOSTS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                "rundll32.exe", "regsvr32.exe"}
LOLBIN_PROXY = {"rundll32.exe", "regsvr32.exe", "mshta.exe", "msiexec.exe"}
RE_ENC = re.compile(r"(?i)(-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}|frombase64string)")
RE_CRADLE = re.compile(r"(?i)(downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|"
                       r"certutil(\.exe)?\s+.*-urlcache|bitsadmin\s+/transfer|curl\s+-o)")
RE_USERPATH = re.compile(r"(?i)\\(appdata|temp|users\\public|programdata)\\")
RE_RECON = re.compile(r"(?i)\b(whoami|nltest|net(\.exe)?\s+group|adfind|dsquery|net(\.exe)?\s+user\s+/domain)\b")
RE_CRED = re.compile(r"(?i)(lsass|comsvcs(\.dll)?,?\s*#?minidump|sekurlsa|procdump.*-ma)")


@dataclass
class Signal:
    name: str
    weight: int
    tactic: str
    hard: bool = False
    detail: str = ""


@dataclass
class Verdict:
    decision: str                  # escalate | review | suppress
    score: int
    tactics: list[str]
    signals: list[Signal]
    modifiers: list[str] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict:
        return {"decision": self.decision, "score": self.score, "tactics": self.tactics,
                "signals": [s.__dict__ for s in self.signals], "modifiers": self.modifiers,
                "reason": self.reason}


def extract_signals(ev: Evidence) -> list[Signal]:
    sig: list[Signal] = []
    by_pid = {n.pid: n for n in ev.tree}
    for n in ev.tree:
        name = (n.name or "").lower()
        parent = by_pid.get(n.parent_pid)
        pname = (parent.name or "").lower() if parent else ""
        cmd = n.cmdline or ""
        if pname in OFFICE and name in SCRIPT_HOSTS:
            sig.append(Signal("office_spawns_script_host", 40, "execution", detail=f"{pname} -> {name}"))
        if name in ("powershell.exe", "pwsh.exe") and RE_ENC.search(cmd):
            sig.append(Signal("encoded_powershell", 20, "stealth", detail=cmd[:120]))
        if RE_CRADLE.search(cmd):
            sig.append(Signal("download_cradle", 20, "command-and-control", detail=cmd[:120]))
            if RE_USERPATH.search(cmd):
                sig.append(Signal("payload_staged_to_writable_path", 15, "execution", detail=cmd[:120]))
        if name in LOLBIN_PROXY and (RE_USERPATH.search(cmd) or "http" in cmd.lower()):
            sig.append(Signal("lolbin_proxy_execution", 25, "stealth", detail=cmd[:120]))
        if RE_RECON.search(cmd):
            sig.append(Signal("discovery_commands", 10, "discovery", detail=cmd[:80]))
        if RE_CRED.search(cmd):
            sig.append(Signal("credential_dumping", 60, "credential-access", hard=True, detail=cmd[:120]))
        if n.signed is False and n.sha256 and ev.hash_prevalence.get(n.sha256, 99) <= 2:
            sig.append(Signal("rare_unsigned_binary", 20, "execution",
                              detail=f"{n.name} seen on {ev.hash_prevalence.get(n.sha256)} host(s)"))
    for h in ev.tip_hits:
        hard = h.get("score", 0) >= 75
        sig.append(Signal("tip_match", 50 if hard else 25, "command-and-control", hard=hard,
                          detail=f"{h['value']} score={h.get('score')} tags={','.join(h.get('tags') or [])[:60]}"))
    # Collapse duplicates (same signal name) keeping the strongest.
    best: dict[str, Signal] = {}
    for s in sig:
        if s.name not in best or s.weight > best[s.name].weight:
            best[s.name] = s
    return list(best.values())


def decide(ev: Evidence) -> Verdict:
    sigs = extract_signals(ev)
    ctx = ev.context
    mods: list[str] = []
    soft = sum(s.weight for s in sigs if not s.hard)
    hard = sum(s.weight for s in sigs if s.hard)

    # Context discounts apply ONLY to soft signals.
    if ctx.get("user_privileged") and ctx.get("is_admin_host"):
        soft = int(soft * 0.5)
        mods.append("privileged user on admin host: soft signals x0.5")
    elif ctx.get("user_privileged") and not ctx.get("is_admin_host"):
        # Admin credentials on an ordinary workstation is a posture problem at
        # best and credential exposure at worst - it raises, never lowers.
        soft += 15
        mods.append("privileged account used off an admin host: +15")
    if ctx.get("change_window"):
        soft = int(soft * 0.7)
        mods.append(f"inside approved change {ctx['change_window']}: soft signals x0.7")
    score = soft + hard
    crit = ctx.get("criticality", 3)
    if crit >= 5:
        score = int(score * 1.3)
        mods.append("crown-jewel asset: x1.3")
    elif crit == 4:
        score = int(score * 1.15)
        mods.append("high-criticality asset: x1.15")
    if not ctx.get("asset_known", True):
        score += 10
        mods.append("asset not in CMDB: +10 (unknown assets are a finding on their own)")
    score = min(score, 100)
    tactics = sorted({s.tactic for s in sigs})

    if any(s.hard for s in sigs):
        return Verdict("escalate", score, tactics, sigs, mods,
                       "hard signal present - context cannot discount it")
    if score >= 70 and len(tactics) >= 2:
        return Verdict("escalate", score, tactics, sigs, mods, f"score {score} across {len(tactics)} tactics")
    if score >= 40:
        return Verdict("review", score, tactics, sigs, mods, "material signal, context incomplete - human review")
    return Verdict("suppress", score, tactics, sigs, mods,
                   "explained by context / below threshold - kept as risk record, not queued")
