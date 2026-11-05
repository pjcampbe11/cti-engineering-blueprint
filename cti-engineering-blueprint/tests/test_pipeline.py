"""
End-to-end and unit tests. Run:  python -m unittest discover -s tests -v

Everything runs offline against the synthetic samples, so these tests can sit
in CI and gate every change to collectors, scoring, Sigma rules and YARA.
"""

import json
import tempfile
import unittest
from pathlib import Path

from ctikit import models, scoring, stix_export, hypothesis, pipeline, attack, sigma_tools
from ctikit.anomali import ThreatStreamClient

ROOT = Path(__file__).resolve().parent.parent
HYP1 = ROOT / "hypotheses" / "HYP-2026-001-helpdesk-idp-takeover.yaml"
HYP2 = ROOT / "hypotheses" / "HYP-2026-002-rag-assistant-prompt-injection.yaml"


class TestModels(unittest.TestCase):
    def test_detect_and_refang(self):
        self.assertEqual(models.detect_type("hxxps://evil[.]example/x"), models.TYPE_URL)
        self.assertEqual(models.detect_type("evil[.]example"), models.TYPE_DOMAIN)
        self.assertEqual(models.detect_type("a" * 64), models.TYPE_SHA256)
        self.assertEqual(models.detect_type("not an ioc"), models.TYPE_UNKNOWN)

    def test_private_ip_dropped_and_doc_range_toggle(self):
        models.ALLOW_DOC_RANGES = False
        self.assertIsNone(models.make_observable("10.1.2.3", "t"))
        self.assertIsNone(models.make_observable("192.0.2.5", "t"))
        models.ALLOW_DOC_RANGES = True
        self.assertIsNotNone(models.make_observable("192.0.2.5", "t"))
        self.assertIsNone(models.make_observable("10.1.2.3", "t"))  # still private

    def test_ip_port_split(self):
        models.ALLOW_DOC_RANGES = True
        o = models.make_observable("203.0.113.9:8041", "t")
        self.assertEqual(o.value, "203.0.113.9")
        self.assertIn("port:8041", o.tags)

    def test_merge_corroboration(self):
        models.ALLOW_DOC_RANGES = True
        a = models.make_observable("evil.example", "feedA", source_confidence=40)
        b = models.make_observable("EVIL.example", "feedB", source_confidence=80)
        self.assertEqual(a.key, b.key)
        a.merge(b)
        self.assertEqual(a.sources, ["feedA", "feedB"])
        self.assertEqual(a.source_confidence, 80)


class TestScoring(unittest.TestCase):
    def test_dual_use_hash_never_blocked(self):
        o = models.Observable(value="b" * 64, type="file:sha256", sources=["x"],
                              malware_family="ScreenConnect", source_confidence=100)
        o.enrichment["vt"] = {"malicious": 60, "harmless": 0, "suspicious": 0, "undetected": 0}
        scoring.apply([o], lambda _: True)
        self.assertEqual(o.action, "hunt")

    def test_expiry_set(self):
        o = models.Observable(value="evil.example", type="domain-name", sources=["x"],
                              first_seen="2020-01-01T00:00:00.000Z")
        scoring.apply([o], lambda _: False)
        self.assertEqual(o.status, "expired")


class TestHypothesis(unittest.TestCase):
    def test_load_both(self):
        self.assertEqual(hypothesis.load(HYP1).id, "HYP-2026-001")
        self.assertIn("AML.T0051.001", hypothesis.load(HYP2).atlas_ids)

    def test_rejects_unfalsifiable(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
            fh.write(HYP1.read_text().replace("refute_if:", "refute_if_removed:"))
        with self.assertRaises(hypothesis.HypothesisError):
            hypothesis.load(fh.name)


class TestStix(unittest.TestCase):
    def test_pattern_escape_and_roundtrip(self):
        o = models.Observable(value="https://x.example/a'b", type="url", sources=["s"])
        pat = stix_export.pattern_for(o)
        self.assertIn("\\'", pat)
        back = stix_export.indicators_to_observables(
            [{"type": "indicator", "pattern_type": "stix", "pattern": pat}], "s")
        self.assertEqual(back[0].value, o.value)

    def test_deterministic_ids(self):
        h = hypothesis.load(HYP1)
        o = models.Observable(value="evil.example", type="domain-name", sources=["s"])
        b1 = stix_export.build_bundle([o], hypothesis=h, producer="p")
        b2 = stix_export.build_bundle([o], hypothesis=h, producer="p")
        ids = lambda b: sorted(x["id"] for x in b["objects"] if x["type"] == "indicator")
        self.assertEqual(ids(b1), ids(b2))


class TestEndToEnd(unittest.TestCase):
    def test_offline_pipeline_hyp1(self):
        with tempfile.TemporaryDirectory() as d:
            res = pipeline.run(str(HYP1), offline=True, out_root=Path(d))
            out = Path(res["out_dir"])
            for f in ("stix_bundle.json", "attack_navigator_layer.json", "technical_report.md",
                      "executive_summary.md", "cti_threat_intel_lookup.csv", "savedsearches.conf",
                      "threatstream_patch_payload.json", "metrics.json"):
                self.assertTrue((out / f).exists(), f)
            m = res["metrics"]
            self.assertTrue(m["stix_bundle_valid"])
            self.assertEqual(m["sigma_errors"], 0)
            self.assertGreater(m["corroborated_multi_source"], 0)
            # The private 10.x sandbox-noise IP must never reach any output.
            self.assertNotIn("10.20.30.40", (out / "observables.json").read_text())
            # Signed ScreenConnect installer hash must not be staged for blocking.
            payload = json.loads((out / "threatstream_patch_payload.json").read_text())
            self.assertFalse(any(x["itype"] == "mal_md5" for x in payload["objects"]))

    def test_validate_repo_clean(self):
        self.assertEqual(pipeline.validate_repo()["errors"], [])

    def test_coverage_states(self):
        h = hypothesis.load(HYP1)
        rows = attack.coverage(h, sigma_tools.techniques_in_repo(ROOT / "detections" / "sigma"))
        states = {r["technique"]: r["state"] for r in rows}
        self.assertEqual(states["T1219"], "covered")
        self.assertEqual(states["T1567.002"], "gap")


if __name__ == "__main__":
    unittest.main()
