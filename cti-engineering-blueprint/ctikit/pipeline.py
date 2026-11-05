"""
pipeline.py - orchestrates one hypothesis end to end.

    Direction     load + validate hypothesis
    Collection    run collectors (feeds, TIP, TAXII), KEV
    Processing    dedupe -> enrich (VT/GTI) -> tag TTPs -> score/action/expiry
    Analysis      relevance filter, ATT&CK/ATLAS coverage vs detection repo
    Production    STIX 2.1 bundle, Navigator layer, Sigma->SPL, YARA, lookup CSV
    Dissemination exec summary + technical report, TIP/SIEM payloads (dry-run by default)
    Feedback      metrics.json

Each stage writes its artifact to out/<HYP-ID>/ so a reviewer can inspect
the intermediate state - the same property you want from a SOAR playbook.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from . import (attack, collectors, enrich, hypothesis as hyp_mod, metrics as met,
               models, report, scoring, sigma_tools, splunk, stix_export, yara_tools)
from .anomali import ThreatStreamClient

log = logging.getLogger("ctikit.pipeline")
ROOT = Path(__file__).resolve().parent.parent

# Lightweight tag -> ATT&CK mapping. In production this lives in the TIP as
# tag/threat-model associations; here it shows the concept: analysts encode
# "this kind of indicator evidences this technique" once, and every future
# indicator with that tag inherits the mapping.
TAG_TO_TTP = {
    "rmm": ["T1219"], "screenconnect": ["T1219"], "anydesk": ["T1219"],
    "helpdesk": ["T1656"], "sso-phish": ["T1583.001"], "okta": ["T1583.001"],
}


def tag_ttps(observables) -> None:
    for o in observables:
        for t in o.tags:
            for tid in TAG_TO_TTP.get(t.lower(), []):
                if tid not in o.attack_techniques:
                    o.attack_techniques.append(tid)


def run(hypothesis_path: str, offline: bool = True, push: bool = False,
        out_root: Path | None = None) -> dict:
    t0 = time.time()
    models.ALLOW_DOC_RANGES = offline  # demo data lives in RFC 5737 space
    hyp = hyp_mod.load(hypothesis_path)
    out = (out_root or ROOT / "out") / hyp.id
    out.mkdir(parents=True, exist_ok=True)
    log.info("[direction] %s - %s", hyp.id, hyp.title)

    # ---- Collection ------------------------------------------------------
    raw, feed_stats = collectors.collect_all(offline)
    kev_all = collectors.cisa_kev(offline)
    # Keep KEV entries whose product appears in the hypothesis relevance terms.
    terms = [t.lower() for b in ("families", "tags") for t in (hyp.raw.get("relevance", {}).get(b) or [])]
    kev = [v for v in kev_all if any(t in f"{v.get('product', '')} {v.get('vendorProject', '')}".lower()
                                     for t in terms)]
    log.info("[collection] %d raw observables from %d feeds, %d relevant KEV", len(raw), len(feed_stats), len(kev))

    # ---- Processing ------------------------------------------------------
    obs = collectors.dedupe(raw)
    n_enriched = enrich.enrich_vt(obs, offline)
    tag_ttps(obs)
    scoring.apply(obs, hyp.is_relevant)
    log.info("[processing] %d unique, %d enriched", len(obs), n_enriched)
    (out / "observables.json").write_text(json.dumps([o.to_dict() for o in obs], indent=2))

    # ---- Analysis --------------------------------------------------------
    det_inventory = sigma_tools.techniques_in_repo(ROOT / "detections" / "sigma")
    rows = attack.coverage(hyp, det_inventory)
    attack.write_layer(attack.navigator_layer(hyp, rows), out / "attack_navigator_layer.json")
    (out / "coverage.json").write_text(json.dumps(rows, indent=2))
    relevant = [o for o in obs if "hypothesis-relevant" in o.tags and o.status != "expired"]
    log.info("[analysis] %d relevant observables; coverage %s",
             len(relevant), {r["technique"]: r["state"] for r in rows})

    # ---- Production ------------------------------------------------------
    tech_names = {t["id"]: t.get("name", t["id"]) for t in hyp.raw.get("expected_ttps", [])}
    bundle = stix_export.build_bundle(relevant, hypothesis=hyp, producer="Bank CTI (demo)",
                                      techniques=tech_names)
    stix_ok, stix_msg = stix_export.validate(bundle)
    (out / "stix_bundle.json").write_text(json.dumps(bundle, indent=2))
    sigma_res = sigma_tools.convert_to_spl(ROOT / "detections" / "sigma", out)
    hashrule = yara_tools.hash_set_rule(relevant, hyp.id)
    if hashrule:
        (out / f"{hyp.id}_hashset.yar").write_text(hashrule)
    yara_res = yara_tools.compile_check(ROOT / "detections" / "yara", [hashrule])
    n_lookup = splunk.write_lookup(relevant, out / "cti_threat_intel_lookup.csv", hyp.id)
    log.info("[production] STIX: %s | Sigma->SPL: %s | YARA: %s | lookup rows: %d",
             stix_msg, sigma_res, yara_res, n_lookup)

    # ---- Dissemination (dry-run unless --push) ---------------------------
    pushable = [o for o in relevant if o.action in ("block", "detect")]
    ts_payload = ThreatStreamClient.build_patch_payload(pushable, source=f"ctikit {hyp.id}")
    if push:
        ts_res = ThreatStreamClient.from_env().import_without_approval(ts_payload, dry_run=False)
        hec_res = splunk.send_hec(splunk.hec_events(relevant, hyp.id), dry_run=False)
    else:
        ts_res = ThreatStreamClient("https://example.invalid", "dry", "run") \
            .import_without_approval(ts_payload, dry_run=True, out_dir=out)
        hec_res = splunk.send_hec(splunk.hec_events(relevant, hyp.id), dry_run=True, out_dir=out)

    # ---- Feedback --------------------------------------------------------
    m = met.compute(len(raw), obs, feed_stats, rows, sigma_res, stix_ok, time.time() - t0)
    m["yara_rules_compiled"] = yara_res.get("checked", 0)
    m["lookup_rows"] = n_lookup
    m["threatstream_objects_staged"] = len(ts_payload["objects"])
    (out / "metrics.json").write_text(json.dumps(m, indent=2))

    artifacts = sorted(p.name for p in out.iterdir())
    (out / "executive_summary.md").write_text(report.executive_summary(hyp, obs, rows, kev))
    (out / "technical_report.md").write_text(
        report.technical_report(hyp, obs, rows, kev, m, artifacts + ["executive_summary.md", "technical_report.md"]))
    log.info("[dissemination] reports written to %s", out)
    return {"out_dir": str(out), "metrics": m, "stix": stix_msg, "sigma": sigma_res,
            "yara": yara_res, "threatstream": ts_res, "hec": hec_res}


def validate_repo() -> dict:
    """CI entry point: every hypothesis, Sigma rule and YARA rule must parse."""
    res = {"hypotheses": [], "errors": []}
    for p in sorted((ROOT / "hypotheses").glob("*.yaml")):
        try:
            res["hypotheses"].append(hyp_mod.load(p).id)
        except Exception as e:  # noqa: BLE001
            res["errors"].append(f"{p.name}: {e}")
    tmp = ROOT / "out" / "_ci"
    s = sigma_tools.convert_to_spl(ROOT / "detections" / "sigma", tmp)
    res["errors"] += s.get("errors", [])
    y = yara_tools.compile_check(ROOT / "detections" / "yara")
    if not y.get("skipped"):
        res["errors"] += y.get("errors", [])
    res["sigma_converted"], res["yara_checked"] = s.get("converted"), y.get("checked")
    return res
