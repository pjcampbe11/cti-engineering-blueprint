"""
Exercises the LIVE code paths (TAXII 2.1 client, ThreatStream client, HTTP
retry) against a local mock server, so the network clients are tested without
real credentials. The mock mimics the documented response shapes.
"""

import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"

from ctikit.taxii import TaxiiClient            # noqa: E402
from ctikit.anomali import ThreatStreamClient   # noqa: E402
from ctikit import models                       # noqa: E402

CALLS = {"429": 0, "patch_body": None}


class Mock(BaseHTTPRequestHandler):
    def log_message(self, *a):  # keep test output clean
        pass

    def _json(self, code, obj, ctype="application/json", extra=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = self.path
        if p.startswith("/api1/collections/c1/objects/"):
            assert self.headers["Accept"].startswith("application/taxii+json;version=2.1")
            if "next=page2" in p:
                return self._json(200, {"more": False, "objects": [
                    {"type": "indicator", "pattern_type": "stix", "id": "indicator--2",
                     "pattern": "[ipv4-addr:value = '203.0.113.9']"}]},
                    "application/taxii+json;version=2.1")
            return self._json(200, {"more": True, "next": "page2", "objects": [
                {"type": "indicator", "pattern_type": "stix", "id": "indicator--1",
                 "pattern": "[domain-name:value = 'evil.example']"}]},
                "application/taxii+json;version=2.1")
        if p.startswith("/api/v2/intelligence/"):
            assert self.headers["Authorization"] == "apikey u:k"
            # First call: rate limited once, to prove retry works.
            if CALLS["429"] == 0:
                CALLS["429"] += 1
                return self._json(429, {"error": "slow down"}, extra={"Retry-After": "0"})
            if "offset=1" in p:
                return self._json(200, {"meta": {"next": None}, "objects": [
                    {"value": "203.0.113.10", "itype": "c2_ip", "confidence": 70, "tags": []}]})
            return self._json(200, {"meta": {"next": "/api/v2/intelligence/?limit=1&offset=1"},
                                    "objects": [{"value": "evil2.example", "itype": "mal_domain",
                                                 "confidence": 80, "tags": [{"name": "UNC3944"}]}]})
        self._json(404, {})

    def do_PATCH(self):
        n = int(self.headers["Content-Length"])
        CALLS["patch_body"] = json.loads(self.rfile.read(n))
        self._json(202, {"success": True, "import_session_id": None})

    def do_POST(self):
        n = int(self.headers["Content-Length"])
        body = json.loads(self.rfile.read(n))
        self._json(202, {"id": "status-1", "status": "pending", "total_count": len(body["objects"])},
                   "application/taxii+json;version=2.1")


class TestLiveClients(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Mock)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        models.ALLOW_DOC_RANGES = True

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_taxii_pagination_and_publish(self):
        c = TaxiiClient("user", "pw")
        objs = list(c.get_objects(f"{self.base}/api1/collections/c1", types=["indicator"]))
        self.assertEqual([o["id"] for o in objs], ["indicator--1", "indicator--2"])
        st = c.add_objects(f"{self.base}/api1/collections/c1", objs)
        self.assertEqual(st["total_count"], 2)

    def test_threatstream_search_retry_paging_and_patch(self):
        c = ThreatStreamClient(self.base, "u", "k")
        objs = c.search(limit=10, status="active")
        self.assertEqual([o["value"] for o in objs], ["evil2.example", "203.0.113.10"])
        self.assertEqual(CALLS["429"], 1)  # one rate-limit absorbed by retry
        obs = [ThreatStreamClient.to_observable(o) for o in objs]
        self.assertEqual(obs[0].threat_actor, "UNC3944")
        payload = ThreatStreamClient.build_patch_payload(obs, source="test")
        r = c.import_without_approval(payload, dry_run=False)
        self.assertTrue(r["success"])
        self.assertEqual(CALLS["patch_body"]["meta"]["intelligence_source"], "test")


if __name__ == "__main__":
    unittest.main()
