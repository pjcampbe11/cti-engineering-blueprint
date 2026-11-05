"""
attack.py - Analysis phase: ATT&CK / ATLAS mapping and detection coverage.

What it produces:
  * A coverage table: for each technique the hypothesis expects, is there a
    detection in the repo, and which one?
  * An ATT&CK Navigator layer (JSON) you can drop into
    https://mitre-attack.github.io/attack-navigator/ - green = covered,
    red = gap, with the data source needed in the comment. This is the single
    best visual for a CTI manager or CISO conversation.

Version notes to carry into the interview:
  * ATT&CK v19 (Apr 2026) split the old Defense Evasion tactic (TA0005) into
    two tactics, Stealth and Impair Defenses. Mappings written against
    "defense-evasion" need to be re-pointed.
  * ATT&CK v20 (Oct 13, 2026) is current and added Enterprise techniques for
    direct/indirect prompt injection and AI-enabled exfiltration.
  * ATLAS IDs (AML.T####) are not Navigator Enterprise techniques; they are
    reported in the coverage table and the STIX bundle, and can be loaded
    into the ATLAS Navigator separately.
"""

from __future__ import annotations

import json

ATTACK_VERSION = "20"     # update when MITRE ships (April / October majors)
NAVIGATOR_VERSION = "5.1.0"
LAYER_VERSION = "4.5"


def coverage(hypothesis, detections_by_technique: dict[str, list[str]]) -> list[dict]:
    """Join expected TTPs to the detection inventory.

    A parent technique counts as covered by a sub-technique detection only
    partially - we flag that rather than claim full coverage.
    """
    rows = []
    for t in hypothesis.raw.get("expected_ttps", []):
        tid = t["id"].upper() if not t["id"].startswith("AML.") else t["id"]
        exact = detections_by_technique.get(tid, [])
        parent = detections_by_technique.get(tid.split(".")[0], []) if "." in tid else []
        children = [r for k, v in detections_by_technique.items()
                    if k.startswith(tid + ".") for r in v]
        if exact:
            state = "covered"
        elif parent or children:
            state = "partial"
        else:
            state = "gap"
        rows.append({"technique": tid, "name": t.get("name", ""), "state": state,
                     "detections": exact or parent or children,
                     "data_sources": t.get("data_sources", []),
                     "framework": "ATLAS" if tid.startswith("AML.") else "ATT&CK"})
    return rows


def navigator_layer(hypothesis, rows: list[dict]) -> dict:
    colors = {"covered": "#31a354", "partial": "#fec44f", "gap": "#de2d26"}
    scores = {"covered": 100, "partial": 50, "gap": 0}
    techs = []
    for r in rows:
        if r["framework"] != "ATT&CK":
            continue
        techs.append({
            "techniqueID": r["technique"],
            "score": scores[r["state"]],
            "color": colors[r["state"]],
            "comment": (f"{r['state'].upper()} | detections: {', '.join(r['detections']) or 'none'}"
                        f" | data sources: {', '.join(r['data_sources'])}"),
            "enabled": True,
            "metadata": [{"name": "hypothesis", "value": hypothesis.id}],
        })
    return {
        "name": f"{hypothesis.id} expected TTP coverage",
        "versions": {"attack": ATTACK_VERSION, "navigator": NAVIGATOR_VERSION,
                     "layer": LAYER_VERSION},
        "domain": "enterprise-attack",
        "description": hypothesis.title,
        "techniques": techs,
        "legendItems": [{"label": "Covered", "color": colors["covered"]},
                        {"label": "Partial (parent/sub-technique only)", "color": colors["partial"]},
                        {"label": "Gap", "color": colors["gap"]}],
        "showTacticRowBackground": True,
        "selectTechniquesAcrossTactics": True,
    }


def write_layer(layer: dict, path) -> None:
    with open(path, "w") as fh:
        json.dump(layer, fh, indent=2)
