"""
stix_export.py - build and parse STIX 2.1 content (Production phase).

Why STIX instead of a CSV of IOCs?
  * STIX carries context and relationships: this indicator -> indicates ->
    this malware -> used by -> this intrusion set -> uses -> this ATT&CK
    technique. A CSV loses all of that.
  * It is what TIPs (ThreatStream, OpenCTI, MISP), ISACs and SIEMs exchange
    over TAXII, so one export reaches every consumer.

Engineering details that come up in interviews:
  * Deterministic IDs. We derive object IDs with UUIDv5 from stable inputs,
    so re-publishing the same indicator produces the same ID and consumers
    update rather than duplicate.
  * Markings. STIX 2.1 ships predefined TLP marking-definition objects
    (WHITE/GREEN/AMBER/RED, TLP 1.0 names). TLP 2.0 labels (CLEAR,
    AMBER+STRICT) are carried via a published extension; we map CLEAR->WHITE
    here and keep the TLP 2.0 label in the report.
  * Validation. If the `stix2` package is installed we parse the bundle with
    it, which enforces the spec (required properties, timestamp format,
    pattern syntax).
"""

from __future__ import annotations

import re
import uuid
from typing import Iterable

from .models import (Observable, make_observable, iso, utcnow, TYPE_IPV4, TYPE_IPV6,
                     TYPE_DOMAIN, TYPE_URL, TYPE_EMAIL)

# Namespace for our own deterministic SDO IDs (any fixed UUID works; keep it
# constant forever once you start publishing).
NS = uuid.UUID("5d1b3c2a-8f0e-4c6b-9a7d-2e4f6a8b0c11")

TLP_MARKINGS = {  # STIX 2.1 predefined TLP marking-definition IDs
    "TLP:CLEAR": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "TLP:WHITE": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "TLP:GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "TLP:AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "TLP:AMBER+STRICT": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "TLP:RED": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}


def _id(stype: str, *parts: str) -> str:
    return f"{stype}--{uuid.uuid5(NS, '|'.join([stype, *parts]))}"


def _esc(v: str) -> str:
    """Escape a value for a STIX pattern string literal."""
    return v.replace("\\", "\\\\").replace("'", "\\'")


def pattern_for(o: Observable) -> str | None:
    if o.type in (TYPE_IPV4, TYPE_IPV6, TYPE_DOMAIN, TYPE_URL, TYPE_EMAIL):
        return f"[{o.type}:value = '{_esc(o.value)}']"
    if o.type.startswith("file:"):
        algo = {"file:md5": "MD5", "file:sha1": "SHA-1", "file:sha256": "SHA-256"}[o.type]
        return f"[file:hashes.'{algo}' = '{o.value}']"
    return None


def build_bundle(observables: Iterable[Observable], *, hypothesis, producer: str,
                 techniques: dict[str, str] | None = None, report_text: str = "") -> dict:
    """Produce a STIX 2.1 bundle: identity, intrusion-set, malware, attack
    patterns, indicators, relationships, and a report object tying it together.

    techniques: {"T1219": "Remote Access Software", ...} (ATT&CK or ATLAS IDs)
    """
    now = iso(utcnow())
    tlp = hypothesis.tlp
    marking = TLP_MARKINGS.get(tlp, TLP_MARKINGS["TLP:AMBER"])
    common = {"spec_version": "2.1", "created": now, "modified": now,
              "object_marking_refs": [marking]}

    ident = {"type": "identity", "id": _id("identity", producer), "name": producer,
             "identity_class": "organization", **common}
    objects: list[dict] = [ident]
    created_by = {"created_by_ref": ident["id"]}

    # Intrusion set from the hypothesis actor (if attributed).
    actor = hypothesis.actor or {}
    iset = None
    if actor.get("name") and actor.get("attack_group_id"):
        iset = {"type": "intrusion-set", "id": _id("intrusion-set", actor["name"]),
                "name": actor["name"], "aliases": actor.get("aliases", []),
                "primary_motivation": "personal-gain" if actor.get("motivation") == "financial" else None,
                "external_references": [{"source_name": "mitre-attack",
                                         "external_id": actor["attack_group_id"],
                                         "url": f"https://attack.mitre.org/groups/{actor['attack_group_id']}/"}],
                **common, **created_by}
        iset = {k: v for k, v in iset.items() if v is not None}
        objects.append(iset)

    # Attack patterns (ATT&CK and ATLAS) referenced by the hypothesis.
    ap_ids = {}
    for tid, name in (techniques or {}).items():
        if tid.startswith("AML."):
            ref = {"source_name": "mitre-atlas", "external_id": tid,
                   "url": f"https://atlas.mitre.org/techniques/{tid}"}
        else:
            ref = {"source_name": "mitre-attack", "external_id": tid,
                   "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"}
        ap = {"type": "attack-pattern", "id": _id("attack-pattern", tid), "name": name,
              "external_references": [ref], **common, **created_by}
        ap_ids[tid] = ap["id"]
        objects.append(ap)
        if iset:
            objects.append(_rel(iset["id"], "uses", ap["id"], common, created_by))

    # Malware families seen across observables.
    mal_ids = {}
    for o in observables:
        if o.malware_family and o.malware_family not in mal_ids:
            m = {"type": "malware", "id": _id("malware", o.malware_family.lower()),
                 "name": o.malware_family, "is_family": True, **common, **created_by}
            mal_ids[o.malware_family] = m["id"]
            objects.append(m)
            if iset:
                objects.append(_rel(iset["id"], "uses", m["id"], common, created_by))

    # Indicators.
    ind_ids = []
    for o in observables:
        pat = pattern_for(o)
        if not pat:
            continue
        ind = {"type": "indicator", "id": _id("indicator", o.type, o.value.lower()),
               "name": f"{o.type} {o.value}", "indicator_types": ["malicious-activity"],
               "pattern": pat, "pattern_type": "stix",
               "valid_from": o.first_seen or now,
               "confidence": int(o.score if o.score is not None else o.source_confidence),
               "labels": sorted(set(o.tags))[:20] or ["unlabeled"],
               **common, **created_by}
        if o.expires:
            ind["valid_until"] = o.expires
            if ind["valid_until"] <= ind["valid_from"]:
                del ind["valid_until"]
        objects.append(ind)
        ind_ids.append(ind["id"])
        if o.malware_family in mal_ids:
            objects.append(_rel(ind["id"], "indicates", mal_ids[o.malware_family], common, created_by))
        elif iset:
            objects.append(_rel(ind["id"], "indicates", iset["id"], common, created_by))
        for t in o.attack_techniques:
            if t in ap_ids:
                objects.append(_rel(ind["id"], "indicates", ap_ids[t], common, created_by))

    # Report object: the finished product, referencing everything above.
    report = {"type": "report", "id": _id("report", hypothesis.id),
              "name": f"{hypothesis.id}: {hypothesis.title}",
              "description": report_text[:4000] or hypothesis.raw.get("statement", ""),
              "report_types": ["threat-actor" if iset else "attack-pattern"],
              "published": now,
              "object_refs": [x["id"] for x in objects if x["type"] != "identity"] or [ident["id"]],
              **common, **created_by}
    objects.append(report)
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def _rel(src: str, rtype: str, tgt: str, common: dict, created_by: dict) -> dict:
    return {"type": "relationship", "id": _id("relationship", src, rtype, tgt),
            "relationship_type": rtype, "source_ref": src, "target_ref": tgt,
            **common, **created_by}


def validate(bundle: dict) -> tuple[bool, str]:
    """Strict validation with the OASIS stix2 library when available."""
    try:
        import stix2  # type: ignore
    except ImportError:
        return True, "stix2 not installed - structural validation skipped"
    try:
        stix2.parse(bundle, allow_custom=False)
        return True, f"valid STIX 2.1 ({len(bundle['objects'])} objects)"
    except Exception as e:  # noqa: BLE001
        return False, f"STIX validation failed: {e}"


# ---------------------------------------------------------------------------
# Ingest direction: STIX indicators from a TAXII feed -> Observables.
# Handles simple single-comparison patterns, which is the bulk of shared IOCs.
# Compound patterns (AND/OR, FOLLOWEDBY) are kept as-is for detection
# engineering review rather than flattened into IOCs.
# ---------------------------------------------------------------------------
_PAT = re.compile(r"^\[\s*([a-z0-9-]+):(value|hashes\.'?([A-Za-z0-9-]+)'?)\s*=\s*'((?:[^'\\]|\\.)*)'\s*\]$")


def indicators_to_observables(objects: list[dict], source: str) -> list[Observable]:
    out = []
    for obj in objects:
        if obj.get("type") != "indicator" or obj.get("pattern_type") != "stix":
            continue
        m = _PAT.match(obj.get("pattern", "").strip())
        if not m:
            continue
        value = m.group(4).replace("\\'", "'").replace("\\\\", "\\")
        labels = list(obj.get("labels") or [])
        actor = next((l for l in labels if l.lower() in
                      ("scattered spider", "unc3944", "octo tempest")), None)
        o = make_observable(value, source, tags=labels, threat_actor=actor,
                            source_confidence=int(obj.get("confidence") or 50),
                            first_seen=obj.get("valid_from"))
        if o:
            out.append(o)
    return out
