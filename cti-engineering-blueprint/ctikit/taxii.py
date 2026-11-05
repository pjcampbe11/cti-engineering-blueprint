"""
taxii.py - minimal TAXII 2.1 client (stdlib only).

TAXII 2.1 (OASIS Standard) is the transport for STIX 2.1. What a CTI engineer
needs to know cold:
  * Discovery:   GET  /taxii2/                       -> api_roots
  * Collections: GET  {api_root}/collections/        -> id, can_read, can_write
  * Read:        GET  {api_root}/collections/{id}/objects/?added_after=...&match[type]=indicator&limit=N
                 Pagination: the envelope carries "more": true and "next"; pass next back.
  * Write:       POST {api_root}/collections/{id}/objects/  body {"objects": [...]}
                 returns a status resource you poll at {api_root}/status/{id}/
  * Media type:  application/taxii+json;version=2.1
  * TAXII 2.1 is effectively pull-based for consumers: you poll collections
    on an interval (channels/push were reserved, never specified). Freshness
    therefore equals your polling interval - say that when asked about
    "real-time" sharing.

Sources you would point this at: FS-ISAC, vendor TAXII feeds, a MISP or
OpenCTI instance, or your own TIP's TAXII server for downstream consumers.
"""

from __future__ import annotations

import base64
import os
from typing import Iterator

from . import http

MEDIA = "application/taxii+json;version=2.1"


class TaxiiClient:
    def __init__(self, user: str | None = None, password: str | None = None,
                 api_key_header: tuple[str, str] | None = None):
        self.headers = {"Accept": MEDIA}
        if user and password:
            tok = base64.b64encode(f"{user}:{password}".encode()).decode()
            self.headers["Authorization"] = f"Basic {tok}"
        if api_key_header:
            self.headers[api_key_header[0]] = api_key_header[1]

    @classmethod
    def from_env(cls) -> "TaxiiClient":
        return cls(os.environ.get("TAXII_USER"), os.environ.get("TAXII_PASSWORD"))

    def discovery(self, server: str) -> dict:
        return http.request("GET", server.rstrip("/") + "/taxii2/", headers=self.headers)

    def collections(self, api_root: str) -> list[dict]:
        r = http.request("GET", api_root.rstrip("/") + "/collections/", headers=self.headers)
        return r.get("collections", [])

    def get_objects(self, collection_url: str, *, added_after: str | None = None,
                    types: list[str] | None = None, limit: int = 500) -> Iterator[dict]:
        """Yield every object, following TAXII 2.1 envelope pagination.

        Persist the X-TAXII-Date-Added-Last header / last date_added you saw
        and pass it as added_after next run - that is how incremental polling
        avoids re-ingesting the whole collection.
        """
        url = collection_url.rstrip("/") + "/objects/"
        params: dict = {"limit": limit}
        if added_after:
            params["added_after"] = added_after
        if types:
            params["match[type]"] = ",".join(types)
        while True:
            env = http.request("GET", url, headers=self.headers, params=params)
            for obj in env.get("objects", []):
                yield obj
            if not env.get("more"):
                break
            params = {"limit": limit, "next": env.get("next")}
            if types:
                params["match[type]"] = ",".join(types)

    def add_objects(self, collection_url: str, objects: list[dict]) -> dict:
        """Publish STIX objects to a writable collection (can_write=true)."""
        hdrs = {**self.headers, "Content-Type": MEDIA}
        return http.request("POST", collection_url.rstrip("/") + "/objects/",
                            headers=hdrs, body={"objects": objects})
