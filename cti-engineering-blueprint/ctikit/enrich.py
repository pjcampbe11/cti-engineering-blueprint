"""
enrich.py - Processing phase: add context to observables.

Primary enrichment source here is VirusTotal / Google Threat Intelligence
(GTI) API v3. GTI is the Google-branded successor product for VT Enterprise;
the v3 REST API and the x-apikey header are shared.

  GET https://www.virustotal.com/api/v3/ip_addresses/{ip}
  GET https://www.virustotal.com/api/v3/domains/{domain}
  GET https://www.virustotal.com/api/v3/files/{hash}
  GET https://www.virustotal.com/api/v3/urls/{url_id}   url_id = base64url(url) without '=' padding

Rate limits matter: public keys are heavily throttled. The cache below means
a re-run never re-spends quota on an indicator enriched in the last N hours.
Other enrichers you would add the same way: passive DNS (DomainTools,
Silent Push), WHOIS age, ASN/geo, Shodan/Censys, internal sightings from
Splunk (has this IOC ever been seen in our logs?).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from pathlib import Path

from . import http
from .models import Observable, TYPE_IPV4, TYPE_IPV6, TYPE_DOMAIN, TYPE_URL, HASH_TYPES

log = logging.getLogger("ctikit.enrich")
SAMPLES = Path(__file__).resolve().parent.parent / "data" / "samples"
CACHE_PATH = Path(os.environ.get("CTIKIT_CACHE", Path.home() / ".ctikit_vt_cache.json"))
CACHE_TTL = 24 * 3600


def _vt_path(o: Observable) -> str | None:
    if o.type in (TYPE_IPV4, TYPE_IPV6):
        return f"ip_addresses/{o.value}"
    if o.type == TYPE_DOMAIN:
        return f"domains/{o.value}"
    if o.type in HASH_TYPES:
        return f"files/{o.value}"
    if o.type == TYPE_URL:
        return "urls/" + base64.urlsafe_b64encode(o.value.encode()).decode().rstrip("=")
    return None


def _summarize_vt(attrs: dict) -> dict:
    """Keep only the fields scoring and analysts use; raw VT objects are huge."""
    stats = attrs.get("last_analysis_stats", attrs)
    keep = {k: stats.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected")}
    for k in ("asn", "as_owner", "country", "creation_date", "registrar",
              "type_description", "signature_info", "popular_threat_classification"):
        if k in attrs:
            keep[k] = attrs[k]
    return keep


def enrich_vt(observables: list[Observable], offline: bool, max_lookups: int = 200) -> int:
    """Enrich in place. Returns the number of observables enriched."""
    if offline:
        sample = json.loads((SAMPLES / "vt_enrichment.json").read_text())
        n = 0
        for o in observables:
            if o.value in sample:
                o.enrichment["vt"] = _summarize_vt(sample[o.value])
                n += 1
            if o.status == "new":
                o.status = "enriched"
        return n

    key = os.environ.get("VT_API_KEY")
    if not key:
        log.warning("VT_API_KEY not set - skipping VirusTotal/GTI enrichment")
        return 0
    cache = json.loads(CACHE_PATH.read_text()) if CACHE_PATH.exists() else {}
    n = 0
    for o in observables[:max_lookups]:
        path = _vt_path(o)
        if not path:
            continue
        hit = cache.get(o.key)
        if hit and time.time() - hit["t"] < CACHE_TTL:
            o.enrichment["vt"] = hit["v"]
        else:
            try:
                r = http.request("GET", f"https://www.virustotal.com/api/v3/{path}",
                                 headers={"x-apikey": key})
                o.enrichment["vt"] = _summarize_vt(r["data"]["attributes"])
                cache[o.key] = {"t": time.time(), "v": o.enrichment["vt"]}
            except Exception as e:  # noqa: BLE001 - 404 = VT has never seen it
                o.enrichment["vt"] = {"error": str(e)[:120]}
        o.status = "enriched"
        n += 1
    CACHE_PATH.write_text(json.dumps(cache))
    return n
