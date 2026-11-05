"""
tip.py - ask the TIP "do we know anything about these observables?"

Two implementations behind one method, lookup(values) -> list of hits:
  * ThreatStreamTIP - live Anomali ThreatStream (GET /api/v2/intelligence/,
    header Authorization: apikey <user>:<key>), active intel only, cached.
  * CsvTIP - reads a lookup CSV. Point it at the cti_threat_intel_lookup.csv
    produced by ctikit (the lifecycle toolkit in this repo) and the two halves
    of the program connect: research produces scored intel, the pivot layer
    consumes it at triage time.

Practitioner note: the TIP answer is only useful with its context - score,
confidence, age, source, actor tags. A bare "match" is how admins get
escalated for hitting a CDN IP that was once in a feed.
"""

from __future__ import annotations

import csv
import os
import time
from pathlib import Path

from .common import http_json, TokenBucket


class CsvTIP:
    def __init__(self, path: Path):
        self.rows = {}
        with Path(path).open() as fh:
            for r in csv.DictReader(fh):
                self.rows[r["indicator"].lower()] = r

    def lookup(self, values: list[str]) -> list[dict]:
        hits = []
        for v in {x.lower() for x in values if x}:
            r = self.rows.get(v)
            if r:
                hits.append({"value": v, "score": int(r.get("score") or 0), "action": r.get("action"),
                             "tags": (r.get("tags") or "").split("|"), "actor": r.get("threat_actor"),
                             "source": "tip-lookup", "expires": r.get("expires")})
        return hits


class ThreatStreamTIP:
    def __init__(self, base: str, user: str, key: str, cache_ttl: int = 3600):
        self.base = base.rstrip("/")
        self.h = {"Authorization": f"apikey {user}:{key}"}
        self.cache: dict[str, tuple[float, list]] = {}
        self.ttl = cache_ttl
        self.bucket = TokenBucket(rate_per_min=60)

    @classmethod
    def from_env(cls):
        return cls(os.environ.get("TS_BASE_URL", "https://api.threatstream.com"),
                   os.environ["TS_USERNAME"], os.environ["TS_API_KEY"])

    def lookup(self, values: list[str]) -> list[dict]:
        hits = []
        for v in {x.lower() for x in values if x}:
            c = self.cache.get(v)
            if c and time.time() - c[0] < self.ttl:
                hits.extend(c[1])
                continue
            r = http_json("GET", f"{self.base}/api/v2/intelligence/", headers=self.h,
                          params={"value": v, "status": "active", "limit": 5},
                          bucket=self.bucket, purpose="tip-lookup")
            found = [{"value": v, "score": int(o.get("confidence") or 0), "action": None,
                      "tags": [t.get("name") for t in o.get("tags") or [] if isinstance(t, dict)],
                      "actor": None, "source": f"threatstream:{o.get('source')}",
                      "itype": o.get("itype"), "expires": o.get("expiration_ts")}
                     for o in r.get("objects", [])]
            self.cache[v] = (time.time(), found)
            hits.extend(found)
        return hits
