from __future__ import annotations

import json
import unittest
from collections import Counter
from pathlib import Path

from hetzner_security.analyzers import hunt
from hetzner_security.collectors.fixture import load_snapshot
from hetzner_security.verification import verify_all

ROOT = Path(__file__).resolve().parents[1]


class BenchmarkTest(unittest.TestCase):
    def test_expected_findings_and_verdicts(self) -> None:
        snapshot = load_snapshot(ROOT / "benchmarks/scenarios/v0.1-insecure.json")
        expected = json.loads(
            (ROOT / "benchmarks/expected-findings/v0.1-insecure.json").read_text()
        )
        findings = verify_all(hunt(snapshot), snapshot)
        self.assertEqual(len(findings), expected["known_problem_count"])
        self.assertEqual(Counter(f.rule_id for f in findings), expected["expected_by_rule"])
        verdicts = Counter(f.status.value for f in findings)
        self.assertEqual(
            {name: verdicts[name] for name in expected["expected_verifier"]},
            expected["expected_verifier"],
        )

    def test_no_real_infrastructure_names(self) -> None:
        raw = (ROOT / "benchmarks/scenarios/v0.1-insecure.json").read_text()
        self.assertIn('"synthetic": true', raw)
        self.assertNotIn("HCLOUD_TOKEN", raw)

    def test_policy_catalog_matches_benchmark_rule_inventory(self) -> None:
        catalog = json.loads((ROOT / "policies/catalog.json").read_text())
        expected = json.loads(
            (ROOT / "benchmarks/expected-findings/v0.1-insecure.json").read_text()
        )
        self.assertEqual(
            {rule["id"] for rule in catalog["rules"]},
            set(expected["expected_by_rule"]),
        )


if __name__ == "__main__":
    unittest.main()
