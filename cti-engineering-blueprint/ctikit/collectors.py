"""
collectors.py - Collection phase connectors.

Each collector does exactly two things:
  1. fetch raw data (live API, or the bundled synthetic sample when offline)
  2. map each record into the normalized Observable via make_observable()

Adding a new feed means adding one function here; nothing downstream changes.
That is the property to point at when someone asks "how would you integrate
our 40 feeds into one view?"

Live endpoints (verify against current vendor docs before production use):
  * abuse.ch ThreatFox / URLhaus / MalwareBazaar - POST APIs; abuse.ch now
    requires a free Auth-Key header (env ABUSECH_AUTH_KEY).
  * CISA KEV - public JSON catalog, no key.
  * Anomali ThreatStream - see anomali.py
  * TAXII 2.1 servers (FS-ISAC, vendors, MISP) - see taxii.py
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Callable, Iterable

from . import http
from .models import Observable, make_observable, parse_ts, iso
from . import stix_export

log = logging.getLogger("ctikit.collect")
SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"


def _sample(name: str) -> dict:
    return json.loads((SAMPLES / name).read_text())


def _ts(value):
    dt = parse_ts(value)
    return iso(dt) if dt else None


# ---------------------------------------------------------------------------
# abuse.ch ThreatFox - IOCs tagged with malware family and confidence.
# ---------------------------------------------------------------------------
def threatfox(offline: bool, days: int = 7) -> list[Observable]:
    if offline:
        data = _sample("threatfox.json")
    else:
        data = http.request(
            "POST", "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": os.environ["ABUSECH_AUTH_KEY"]},
            body={"query": "get_iocs", "days": days})
    out = []
    for r in data.get("data") or []:
        tags = list(r.get("tags") or [])
        family = (r.get("malware_printable") or "").replace(" (abused)", "") or None
        actor = next((t for t in tags if t.lower() in
                      ("scattered spider", "unc3944", "octo tempest")), None)
        o = make_observable(
            r["ioc"], "abusech:threatfox", tags=tags, malware_family=family,
            threat_actor=actor, source_confidence=int(r.get("confidence_level") or 50),
            first_seen=_ts(r.get("first_seen")), last_seen=_ts(r.get("last_seen")))
        if o:
            out.append(o)
    return out


# ---------------------------------------------------------------------------
# abuse.ch URLhaus - malicious URLs. We also emit the URL's host as a domain
# observable, because most controls block on domain, not full URL.
# ---------------------------------------------------------------------------
def urlhaus(offline: bool) -> list[Observable]:
    if offline:
        data = _sample("urlhaus.json")
    else:
        data = http.request(
            "GET", "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/1000/",
            headers={"Auth-Key": os.environ["ABUSECH_AUTH_KEY"]})
    out = []
    for r in data.get("urls") or []:
        if r.get("url_status") == "offline":
            # Offline URLs keep historical value for hunting but should not
            # be pushed to blocking controls; tag rather than drop.
            r.setdefault("tags", []).append("offline")
        tags = list(r.get("tags") or [])
        conf = 70 if r.get("url_status") == "online" else 40
        o = make_observable(r["url"], "abusech:urlhaus", tags=tags,
                            source_confidence=conf, first_seen=_ts(r.get("date_added")))
        if o:
            out.append(o)
            host = r["url"].split("/")[2].split(":")[0]
            d = make_observable(host, "abusech:urlhaus", tags=tags,
                                source_confidence=conf - 10, first_seen=o.first_seen)
            if d:
                out.append(d)
    return out


# ---------------------------------------------------------------------------
# abuse.ch MalwareBazaar - sample hashes (we keep sha256 as the primary).
# ---------------------------------------------------------------------------
def malwarebazaar(offline: bool, selector: str = "time") -> list[Observable]:
    if offline:
        data = _sample("malwarebazaar.json")
    else:
        data = http.request(
            "POST", "https://mb-api.abuse.ch/api/v1/",
            headers={"Auth-Key": os.environ["ABUSECH_AUTH_KEY"]},
            body=b"query=get_recent&selector=" + selector.encode())
    out = []
    for r in data.get("data") or []:
        o = make_observable(
            r["sha256_hash"], "abusech:malwarebazaar", tags=list(r.get("tags") or []),
            malware_family=r.get("signature"), source_confidence=65,
            first_seen=_ts(r.get("first_seen")),
            enrichment={"file_name": r.get("file_name"), "md5": r.get("md5_hash"),
                        "sha1": r.get("sha1_hash")})
        if o:
            out.append(o)
    return out


# ---------------------------------------------------------------------------
# CISA KEV - vulnerabilities, not observables. Returned separately because
# they feed vulnerability management prioritization, not IOC blocking.
# ---------------------------------------------------------------------------
def cisa_kev(offline: bool) -> list[dict]:
    if offline:
        return _sample("cisa_kev.json")["vulnerabilities"]
    data = http.request("GET",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    return data.get("vulnerabilities", [])


# ---------------------------------------------------------------------------
# TIP pull (Anomali ThreatStream) and TAXII pull are thin wrappers so the
# pipeline can treat every source identically.
# ---------------------------------------------------------------------------
def threatstream(offline: bool, query: str | None = None) -> list[Observable]:
    from .anomali import ThreatStreamClient
    if offline:
        objs = _sample("threatstream_intel.json")["objects"]
    else:
        objs = ThreatStreamClient.from_env().search(q=query, limit=500)
    return [o for o in (ThreatStreamClient.to_observable(x) for x in objs) if o]


def taxii(offline: bool, collection_url: str | None = None) -> list[Observable]:
    from .taxii import TaxiiClient
    if offline:
        objects = _sample("taxii_fsisac_bundle.json")["objects"]
    else:
        objects = list(TaxiiClient.from_env().get_objects(collection_url, types=["indicator"]))
    return stix_export.indicators_to_observables(objects, source="taxii:fs-isac")


# Registry used by the pipeline. Order does not matter - dedupe happens after.
REGISTRY: dict[str, Callable[[bool], Iterable[Observable]]] = {
    "threatfox": threatfox,
    "urlhaus": urlhaus,
    "malwarebazaar": malwarebazaar,
    "threatstream": threatstream,
    "taxii": taxii,
}


def collect_all(offline: bool, enabled: list[str] | None = None) -> tuple[list[Observable], dict]:
    """Run every enabled collector. One failing feed never stops the run;
    its failure is recorded in the stats so the metrics show feed health."""
    obs: list[Observable] = []
    stats: dict[str, dict] = {}
    for name, fn in REGISTRY.items():
        if enabled and name not in enabled:
            continue
        try:
            got = list(fn(offline))
            obs.extend(got)
            stats[name] = {"status": "ok", "count": len(got)}
        except Exception as e:  # noqa: BLE001 - feed isolation is the point
            log.error("collector %s failed: %s", name, e)
            stats[name] = {"status": "error", "error": str(e), "count": 0}
    return obs, stats


def dedupe(observables: list[Observable]) -> list[Observable]:
    """Merge duplicates across feeds. Corroboration count survives in
    Observable.sources and feeds the scoring model."""
    merged: dict[str, Observable] = {}
    for o in observables:
        if o.key in merged:
            merged[o.key].merge(o)
        else:
            merged[o.key] = o
    return list(merged.values())
