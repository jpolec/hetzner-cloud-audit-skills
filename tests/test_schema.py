from __future__ import annotations

import json
import unittest
from pathlib import Path

from hetzner_security.analyzers import hunt
from hetzner_security.collectors.fixture import load_snapshot
from hetzner_security.verification import verify_all

ROOT = Path(__file__).resolve().parents[1]


class SchemaContractTest(unittest.TestCase):
    def test_findings_have_required_contract(self) -> None:
        schema = json.loads((ROOT / "schemas/finding.schema.json").read_text())
        required = set(schema["required"])
        snapshot = load_snapshot(ROOT / "benchmarks/scenarios/v0.1-insecure.json")
        for finding in verify_all(hunt(snapshot), snapshot):
            self.assertEqual(set(finding.to_dict()), required)
            self.assertIn(finding.status.value, schema["properties"]["status"]["enum"])
            self.assertIn(finding.severity.value, schema["properties"]["severity"]["enum"])


if __name__ == "__main__":
    unittest.main()
