"""
hypothesis.py - load, validate and query a hypothesis record (Direction phase).

The hypothesis file is the contract for a piece of CTI work. This module:
  * validates that the record has the fields a reviewer will ask about
    (falsifiable statement, evaluation criteria, alternatives, handoffs),
  * exposes the technique list so analysis can compute coverage,
  * provides the relevance filter that trims collected data down to what the
    question actually needs.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from .models import Observable

# Fields a CTI manager will expect to see on every piece of tasked research.
REQUIRED_FIELDS = [
    "id", "title", "status", "tlp", "requirement", "statement",
    "expected_ttps", "collection_plan", "evaluation", "alternatives", "handoffs",
]
VALID_STATUS = {"draft", "active", "validated", "refuted", "parked"}


class HypothesisError(ValueError):
    pass


@dataclass
class Hypothesis:
    raw: dict
    path: Path

    # Convenience accessors so other modules never index raw dicts directly.
    @property
    def id(self) -> str:
        return self.raw["id"]

    @property
    def title(self) -> str:
        return self.raw["title"]

    @property
    def tlp(self) -> str:
        return self.raw.get("tlp", "TLP:AMBER")

    @property
    def actor(self) -> dict:
        return self.raw.get("actor") or {}

    @property
    def technique_ids(self) -> list[str]:
        return [t["id"] for t in self.raw.get("expected_ttps", [])]

    @property
    def attack_ids(self) -> list[str]:
        """ATT&CK Enterprise IDs only (T####)."""
        return [t for t in self.technique_ids if t.startswith("T")]

    @property
    def atlas_ids(self) -> list[str]:
        """MITRE ATLAS IDs only (AML.T####)."""
        return [t for t in self.technique_ids if t.startswith("AML.")]

    def is_relevant(self, obs: Observable) -> bool:
        """Relevance filter.

        Keeps an observable if its actor, malware family, or tags match the
        terms declared in the hypothesis. Matching is case-insensitive
        substring so 'ScreenConnect' matches 'screenconnect_loader'.

        Why filter at all? A TIP may ingest millions of indicators a day. A
        hypothesis-driven workflow asks a narrow question, so only the slice
        that bears on it should flow into the hunt package and report. The
        rest still lives in the TIP for general SOC enrichment.
        """
        rel = self.raw.get("relevance", {}) or {}
        hay = " ".join(filter(None, [
            (obs.threat_actor or ""), (obs.malware_family or ""), " ".join(obs.tags)
        ])).lower()
        for bucket in ("actors", "families", "tags"):
            for term in rel.get(bucket, []) or []:
                if term.lower() in hay:
                    return True
        # Technique overlap also counts: an indicator tagged with a TTP we are
        # testing is relevant even if the actor is unknown.
        return bool(set(obs.attack_techniques) & set(self.technique_ids))


def load(path: str | Path) -> Hypothesis:
    p = Path(path)
    data = yaml.safe_load(p.read_text())
    missing = [f for f in REQUIRED_FIELDS if f not in data]
    if missing:
        raise HypothesisError(f"{p.name}: missing required fields {missing}")
    if data["status"] not in VALID_STATUS:
        raise HypothesisError(f"{p.name}: status must be one of {sorted(VALID_STATUS)}")
    ev = data["evaluation"]
    if not ev.get("confirm_if") or not ev.get("refute_if"):
        # A hypothesis with no refutation criteria cannot be falsified.
        raise HypothesisError(f"{p.name}: evaluation needs confirm_if AND refute_if")
    return Hypothesis(raw=data, path=p)
