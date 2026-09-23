from __future__ import annotations

import json
import unittest
from collections import Counter
from pathlib import Path

from hetzner_security.analyzers import hunt
from hetzner_security.anonymize import anonymize_snapshot, leftovers
from hetzner_security.collectors.fixture import load_snapshot
from hetzner_security.verification import verify_all

FIXTURE = Path(__file__).resolve().parents[1] / "benchmarks" / "scenarios" / "v0.1-insecure.json"


def _raw() -> dict[str, object]:
    raw = json.loads(FIXTURE.read_text())
    # Make it identifying: a company name in names and labels, a public address, an odd admin port, a domain.
    for asset in raw["assets"]:
        asset["name"] = f"acmecorp-{asset['name']}"
        asset.setdefault("labels", {})["project"] = "acmecorp-billing"
    raw["assets"][0]["properties"]["description"] = "billing box for ops@acmecorp.com at acmecorp.com"
    raw["assets"][0]["properties"]["inbound"] = [{"direction": "in", "protocol": "tcp", "port": "49222", "port_from": 49222,
                                                  "port_to": 49222, "sources": ["93.184.216.34/32"]}]
    return raw


class AnonymizeTest(unittest.TestCase):
    def test_no_identifying_strings_survive(self) -> None:
        raw = _raw()
        result = anonymize_snapshot(raw)
        text = json.dumps(result)
        for secret in ("acmecorp", "49222", "93.184.216.34", "ops@"):
            self.assertNotIn(secret, text)
        self.assertEqual(leftovers(raw, result), [])
        self.assertTrue(result["metadata"]["anonymized"])

    def test_findings_survive_anonymization(self) -> None:
        import tempfile

        raw = _raw()
        with tempfile.TemporaryDirectory() as tmp:
            original, anonymized = Path(tmp) / "a.json", Path(tmp) / "b.json"
            original.write_text(json.dumps(raw))
            anonymized.write_text(json.dumps(anonymize_snapshot(raw)))
            counts = [Counter((item.rule_id, item.status.value) for item in verify_all(hunt(snap), snap))
                      for snap in (load_snapshot(original), load_snapshot(anonymized))]
        self.assertEqual(counts[0], counts[1])


if __name__ == "__main__":
    unittest.main()


class CanaryTest(unittest.TestCase):
    """Identifying strings planted in every label and ID field must not survive (reviewer's reproduction)."""

    def test_canaries_do_not_survive(self) -> None:
        raw = {
            "metadata": {"project": "acme-billing"},
            "assets": [
                {"id": "hcloud:server:12345", "type": "server", "name": "acme-db-1", "source": "hcloud_api",
                 "labels": {"environment": "acme-prod", "audit.owner": "alice@acme.com", "audit.ignore": "true",
                            "acme.com/team": "payments", "role": "acme-db", "sensitivity": "high"},
                 "properties": {"id": 12345, "private_net": [{"network": 4711, "ip": "10.0.0.5"}], "volumes": [777],
                                "description": "Acme Corp billing DB, shop.acme.com"}},
                {"id": "hcloud:network:4711", "type": "network", "name": "acme-net", "source": "hcloud_api", "labels": {},
                 "properties": {"id": 4711, "ip_range": "10.0.0.0/16", "servers": [12345]}},
            ],
            "edges": [{"source": "hcloud:network:4711", "target": "hcloud:server:12345", "relation": "contains", "evidence": []}],
        }
        result = anonymize_snapshot(raw)
        text = json.dumps(result).lower()
        for canary in ("acme", "alice", "12345", "4711", "payments", "shop."):
            self.assertNotIn(canary, text, canary)
        labels = result["assets"][0]["labels"]
        self.assertEqual(labels["sensitivity"], "high")
        self.assertEqual(labels["audit.ignore"], "true")
        self.assertEqual(labels["role"], "db")
        # References stay consistent after renumbering.
        server_id = result["assets"][0]["id"].rsplit(":", 1)[-1]
        self.assertEqual(result["assets"][1]["properties"]["servers"], [int(server_id)])
        self.assertEqual(result["edges"][0]["target"], result["assets"][0]["id"])
