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
            severity = finding.severity.value if finding.severity is not None else None
            self.assertIn(severity, schema["properties"]["severity"]["enum"])

    def test_finding_schema_has_only_local_references(self) -> None:
        schema = json.loads((ROOT / "schemas/finding.schema.json").read_text())
        serialized = json.dumps(schema)
        self.assertIn('"$ref": "#/$defs/evidence"', serialized)
        self.assertNotIn("example.invalid/hetzner-security", serialized)

    def test_architecture_recommendation_example_validates(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/architecture-recommendation.schema.json").read_text()
        )
        example = json.loads(
            (ROOT / "examples/findings/architecture-recommendation.json").read_text()
        )
        self.assertEqual(set(example), set(schema["required"]))
        self.assertIn(example["provider"], schema["properties"]["provider"]["enum"])
        self.assertIn(example["status"], schema["properties"]["status"]["enum"])
        self.assertIn(example["risk"], schema["properties"]["risk"]["enum"])


if __name__ == "__main__":
    unittest.main()
