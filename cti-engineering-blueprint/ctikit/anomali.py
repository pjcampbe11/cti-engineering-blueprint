"""
anomali.py - Anomali ThreatStream (TIP) connector.

ThreatStream is the system of record for intelligence in this design: feeds,
ISAC sharing and analyst-curated observables land there; downstream controls
(Splunk, EDR, firewalls) consume from it via ThreatStream Integrator / native
apps; and this connector lets custom automation read and write the same store.

API facts used here (from Anomali's ThreatStream API docs):
  * Auth header:      Authorization: apikey <username>:<api_key>
  * Search:           GET   /api/v2/intelligence/        (v1 is deprecated)
  * Import (no approval): PATCH /api/v2/intelligence/  JSON {"meta": {...}, "objects": [...]}
                      requires the "Approve Intelligence" permission; max 10 MB
  * Import (with approval): POST /api/v2/intelligence/import/  creates an
                      import job an analyst approves in the UI
  * ThreatStream auto-scores domain, IP and URL observables only; other types
    need an explicit confidence.
  * Large / recurring pulls should use the Snapshot API or ThreatStream
    Integrator rather than paging the intelligence endpoint.

Default behavior is DRY RUN: payloads are written to disk, not sent. Writes to
a production TIP should go through change control and the with-approval path
until the automation has earned trust.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import timedelta
from pathlib import Path

from . import http
from .models import (Observable, make_observable, TYPE_IPV4, TYPE_IPV6, TYPE_DOMAIN,
                     TYPE_URL, TYPE_EMAIL, HASH_TYPES, parse_ts, utcnow)

log = logging.getLogger("ctikit.anomali")

# Our observable type -> ThreatStream itype. itypes are instance-configurable;
# confirm against GET /api/v1/itype/ (or your admin) before production use.
# ThreatStream has historically used the md5 itype family for file hashes of
# any algorithm - check how your instance labels sha256 values.
ITYPE_MAP = {
    TYPE_IPV4: "mal_ip", TYPE_IPV6: "mal_ip",
    TYPE_DOMAIN: "mal_domain", TYPE_URL: "mal_url", TYPE_EMAIL: "phish_email",
    "file:md5": "mal_md5", "file:sha1": "mal_md5", "file:sha256": "mal_md5",
}
# Phishing-flavored overrides when the observable is tagged that way.
PHISH_ITYPE = {TYPE_DOMAIN: "phish_domain", TYPE_URL: "phish_url"}


class ThreatStreamClient:
    def __init__(self, base_url: str, username: str, api_key: str, verify_only: bool = False):
        self.base = base_url.rstrip("/")
        self._auth = {"Authorization": f"apikey {username}:{api_key}"}

    @classmethod
    def from_env(cls) -> "ThreatStreamClient":
        return cls(os.environ.get("TS_BASE_URL", "https://api.threatstream.com"),
                   os.environ["TS_USERNAME"], os.environ["TS_API_KEY"])

    # ------------------------------------------------------------------ read
    def search(self, q: str | None = None, limit: int = 1000, **filters) -> list[dict]:
        """Page through /api/v2/intelligence/.

        Example filters: status="active", confidence__gte=70,
        modified_ts__gte="2026-11-01T00:00:00", tags__name="Scattered Spider".
        """
        params = {"limit": min(limit, 1000), **filters}
        if q:
            params["q"] = q
        url = f"{self.base}/api/v2/intelligence/"
        out: list[dict] = []
        while url and len(out) < limit:
            page = http.request("GET", url, headers=self._auth, params=params)
            out.extend(page.get("objects", []))
            nxt = (page.get("meta") or {}).get("next")
            url, params = (f"{self.base}{nxt}" if nxt and nxt.startswith("/") else nxt), None
        return out[:limit]

    # ----------------------------------------------------------------- write
    @staticmethod
    def build_patch_payload(observables: list[Observable], *, source: str,
                            classification: str = "private") -> dict:
        """Build the JSON body for import-without-approval (PATCH).

        meta = settings for every object; objects = per-observable overrides.
        Expiration is set from our lifecycle model so ThreatStream ages the
        indicator out on the same schedule the rest of the pipeline uses.
        """
        objects = []
        for o in observables:
            phishy = any(t in ("sso-phish", "phish", "phishing") for t in o.tags)
            itype = (PHISH_ITYPE.get(o.type) if phishy else None) or ITYPE_MAP.get(o.type)
            if not itype:
                continue
            obj = {
                "value": o.value,
                "itype": itype,
                "confidence": int(o.score if o.score is not None else o.source_confidence),
                "tags": [{"name": t, "tlp": "red"} for t in sorted(set(o.tags))][:50],
            }
            if o.expires:
                obj["expiration_ts"] = o.expires.replace("Z", "")
            objects.append(obj)
        return {"meta": {"classification": classification, "allow_unresolved": True,
                         "intelligence_source": source, "confidence": 50},
                "objects": objects}

    def import_without_approval(self, payload: dict, dry_run: bool = True,
                                out_dir: Path | None = None) -> dict:
        size = len(json.dumps(payload).encode())
        if size > 10 * 1024 * 1024:
            raise ValueError("ThreatStream import payload exceeds 10 MB - batch it")
        if dry_run:
            path = (out_dir or Path(".")) / "threatstream_patch_payload.json"
            path.write_text(json.dumps(payload, indent=2))
            log.info("DRY RUN: ThreatStream PATCH payload written to %s (%d objects)",
                     path, len(payload["objects"]))
            return {"dry_run": True, "path": str(path), "objects": len(payload["objects"])}
        return http.request("PATCH", f"{self.base}/api/v2/intelligence/",
                            headers=self._auth, body=payload)

    def import_with_approval(self, values: list[str], *, confidence: int, threat_type: str,
                             tags: list[str], source: str, dry_run: bool = True,
                             out_dir: Path | None = None) -> dict:
        """Submit an import job that an analyst approves in the ThreatStream UI.

        This is the right default for automation that is still earning trust:
        the machine does the collection and formatting, a human makes the
        publish decision.
        """
        form = {"datatext": "\n".join(values), "confidence": str(confidence),
                "threat_type": threat_type, "classification": "private",
                "intelligence_source": source,
                "tags": json.dumps([{"name": t} for t in tags])}
        if dry_run:
            path = (out_dir or Path(".")) / "threatstream_import_job.json"
            path.write_text(json.dumps(form, indent=2))
            return {"dry_run": True, "path": str(path)}
        import urllib.parse
        return http.request("POST", f"{self.base}/api/v2/intelligence/import/",
                            headers={**self._auth,
                                     "Content-Type": "application/x-www-form-urlencoded"},
                            body=urllib.parse.urlencode(form).encode())

    # -------------------------------------------------------------- mapping
    @staticmethod
    def to_observable(obj: dict) -> Observable | None:
        """Map a ThreatStream intelligence object into our model."""
        tags = [t["name"] if isinstance(t, dict) else str(t) for t in obj.get("tags") or []]
        actor = next((t for t in tags if t.lower() in
                      ("scattered spider", "unc3944", "octo tempest")), None)
        created = parse_ts(obj.get("created_ts"))
        o = make_observable(
            obj.get("value"), f"threatstream:{obj.get('source', 'unknown')}",
            tags=tags + ([obj["itype"]] if obj.get("itype") else []),
            threat_actor=actor, source_confidence=int(obj.get("confidence") or 50),
            first_seen=created.strftime("%Y-%m-%dT%H:%M:%S.000Z") if created else None)
        if o and obj.get("tlp"):
            o.tlp = f"TLP:{str(obj['tlp']).upper()}"
        return o
