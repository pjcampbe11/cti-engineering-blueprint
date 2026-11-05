"""
report.py - Dissemination: turn pipeline output into finished intelligence.

Structure follows how finished intel is consumed:
  * BLUF first. Executives read two sentences; write those two sentences first.
  * Key judgments in estimative language (ICD 203 style probability words)
    with an explicit analytic confidence level. "Likely" is a probability;
    "moderate confidence" is how much we trust the evidence. Keep them apart.
  * Source reliability in Admiralty (NATO) code where it matters.
  * Recommendations per consuming team - each team should be able to find
    its own action in under 30 seconds.
  * Indicators defanged in the appendix; machine-readable copies ship as
    STIX / CSV beside the report, never only inside a PDF.
"""

from __future__ import annotations

from collections import Counter

from .models import defang, utcnow

# ICD 203 expressions of likelihood (for reference in the template/report).
LIKELIHOOD = [
    ("almost no chance / remote", "1-5%"), ("very unlikely / highly improbable", "5-20%"),
    ("unlikely / improbable", "20-45%"), ("roughly even chance", "45-55%"),
    ("likely / probable", "55-80%"), ("very likely / highly probable", "80-95%"),
    ("almost certain / nearly certain", "95-99%"),
]


TEAM_LABELS = {"soc": "SOC", "red_team_purple_team": "Red Team / Purple Team",
               "ai_platform": "AI Platform", "detection_engineering": "Detection Engineering",
               "threat_hunting": "Threat Hunting", "identity_engineering": "Identity Engineering"}


def _team(k: str) -> str:
    return TEAM_LABELS.get(k, k.replace("_", " ").title())


def _coverage_line(rows):
    c = Counter(r["state"] for r in rows)
    total = len(rows) or 1
    return c, round(100 * c.get("covered", 0) / total)


def executive_summary(hyp, observables, rows, kev) -> str:
    c, pct = _coverage_line(rows)
    high = [o for o in observables if o.priority == "high" and o.status != "expired"]
    gaps = [r for r in rows if r["state"] == "gap"]
    name = hyp.actor.get("name")
    who = (f"{name} tradecraft" if hyp.actor.get("attack_group_id")
           else "the tradecraft described in this hypothesis")
    lines = [
        f"# Executive Summary - {hyp.id}",
        f"**{hyp.tlp}** | Prepared {utcnow():%Y-%m-%d} | Owner: {hyp.raw.get('owner', 'CTI')}",
        "",
        "## Bottom line up front",
        (f"External reporting supports the hypothesis that {who} "
         f"({hyp.title}) is relevant to us. Our current detections cover "
         f"{c.get('covered', 0)} of {len(rows)} expected techniques ({pct}%), with "
         f"{len(gaps)} gap(s) that need engineering work before we could reliably see this attack."),
        "",
        "## What we are asking for",
    ]
    for g in gaps[:5]:
        lines.append(f"- Close detection gap **{g['technique']} {g['name']}** "
                     f"(needs: {', '.join(g['data_sources']) or 'data source review'}).")
    h = hyp.raw.get("handoffs", {})
    if "identity_engineering" in h:
        lines.append(f"- Identity control change: {h['identity_engineering']}.")
    lines += [
        "",
        "## Risk view",
        f"- {len(high)} high-priority indicators are live and loaded to the TIP and SIEM lookup.",
        f"- {len(kev)} related known-exploited vulnerabilities flagged to Vulnerability Management.",
        "- Internal hunt (90-day lookback) is in progress; findings will update this assessment.",
        "",
        "_Probability terms follow ICD 203 (e.g., likely = 55-80%)._",
    ]
    return "\n".join(lines) + "\n"


def technical_report(hyp, observables, rows, kev, metrics, artifacts) -> str:
    c, pct = _coverage_line(rows)
    live = [o for o in observables if o.status != "expired" and o.action != "drop"]
    relevant = [o for o in live if "hypothesis-relevant" in o.tags]
    r = hyp.raw
    out = [
        f"# {hyp.id}: {hyp.title}",
        f"**{hyp.tlp}** | Status: {r['status']} | PIR: {r['requirement']['pir']} | Generated {utcnow():%Y-%m-%d %H:%M} UTC",
        "",
        "## 1. Requirement and hypothesis",
        f"**Requirement ({r['requirement']['pir']}):** {r['requirement']['text'].strip()}",
        "",
        f"**Hypothesis:** {r['statement'].strip()}",
        "",
        "**Competing hypotheses (ACH):**",
        *[f"- {a['id']}: {a['text']}" for a in r.get("alternatives", [])],
        "",
        "## 2. Key judgments",
        (f"- KJ1: It is **likely** that the intrusion set described is actively using "
         f"infrastructure relevant to this hypothesis: {len(relevant)} relevant live indicators "
         f"from {len({s for o in relevant for s in o.sources})} distinct sources, "
         f"{sum(1 for o in relevant if len(o.sources) > 1)} corroborated by more than one source. "
         f"*Confidence: moderate* (independent sources, no internal sighting yet).")
        if relevant else
        ("- KJ1: No indicator-level evidence was collected; this is a behavior-driven hypothesis and "
         "the assessment rests on published technique reporting and our own exposure. "
         "Likelihood is **not yet assessed**. *Confidence: low* until internal telemetry is reviewed."),
        (f"- KJ2: Our detection coverage for the expected chain is **{pct}%** "
         f"({c.get('covered', 0)} covered, {c.get('partial', 0)} partial, {c.get('gap', 0)} gap). "
         f"*Confidence: high* (based on our own detection inventory)."),
        ("- KJ3: Hash-based blocking is a poor control for this tradecraft because the tools are "
         "legitimate signed software; behavioral detections and identity process controls carry "
         "the defense. *Confidence: high.*"),
        "",
        "## 3. Detection coverage (ATT&CK / ATLAS)",
        "| Technique | Name | State | Detections | Data sources needed |",
        "|---|---|---|---|---|",
        *[f"| {x['technique']} | {x['name']} | {x['state']} | {', '.join(x['detections']) or '-'} | "
          f"{', '.join(x['data_sources'])} |" for x in rows],
        "",
        "## 4. Recommendations by team",
        *[f"- **{_team(k)}:** {v}" for k, v in r.get("handoffs", {}).items()],
        "",
        "## 5. Evaluation criteria (agreed before analysis)",
        "**Confirm if:**", *[f"- {x}" for x in r["evaluation"]["confirm_if"]],
        "**Refute if:**", *[f"- {x}" for x in r["evaluation"]["refute_if"]],
        "",
        "## 6. Related known-exploited vulnerabilities",
        *([f"- {v['cveID']} - {v.get('vendorProject')} {v.get('product')}: {v.get('vulnerabilityName')} "
           f"(ransomware use: {v.get('knownRansomwareCampaignUse')})" for v in kev] or ["- none"]),
        "",
        "## 7. Pipeline metrics",
        *[f"- {k}: {v}" for k, v in metrics.items() if not isinstance(v, dict)],
        "",
        "## 8. Artifacts",
        *[f"- `{a}`" for a in artifacts],
        "",
        "## Appendix A - Indicators (defanged)",
        "| Indicator | Type | Score | Action | Sources | Expires |",
        "|---|---|---|---|---|---|",
        *[f"| {defang(o.value)} | {o.type} | {o.score} | {o.action} | {len(o.sources)} | {(o.expires or '')[:10]} |"
          for o in sorted(relevant, key=lambda x: -(x.score or 0))],
        "",
    ]
    return "\n".join(out)
