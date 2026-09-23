from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from hetzner_security.analyzers import hunt
from hetzner_security.models import Asset, Snapshot
from hetzner_security.projects import merge_snapshots, project_summary
from hetzner_security.verification import verify_all


def _server(sid: int, name: str, ip: str, environment: str, sources: list[str] | None = None) -> Asset:
    rules = [{"direction": "in", "protocol": "tcp", "port_from": 5432, "port_to": 5432, "sources": sources}] if sources else []
    return Asset(f"hcloud:server:{sid}", "server", name,
                 {"public_ip": True, "firewall_attached": True, "inbound": rules, "public_net": {"ipv4": {"ip": ip}}},
                 {"environment": environment}, "hcloud_api")


def _write(tmp: Path, name: str, project: str, assets: list[Asset]) -> Path:
    shared = Asset("hcloud:server_type:cx22", "server_type", "cx22", {"name": "cx22"}, {}, "hcloud_api")
    path = tmp / f"{name}.json"
    path.write_text(json.dumps(Snapshot(assets=[*assets, shared], metadata={"project": project, "collected_at": "2026-09-23T00:00:00+00:00",
                                                                            "coverage": {"server": {"status": "collected"}}}).to_dict()))
    return path


class MultiProjectTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._dir.name)

    def tearDown(self) -> None:
        self._dir.cleanup()

    def test_merge_tags_projects_and_dedupes_catalog(self) -> None:
        merged = merge_snapshots([
            _write(self.tmp, "a", "prod", [_server(1, "db", "203.0.113.5", "production")]),
            _write(self.tmp, "b", "staging", [_server(2, "worker", "198.51.100.9", "staging")]),
        ])
        self.assertEqual([item["name"] for item in merged.metadata["projects"]], ["prod", "staging"])
        self.assertEqual(sum(1 for asset in merged.assets if asset.type == "server_type"), 1)
        self.assertIn("prod:server", merged.metadata["coverage"])
        self.assertEqual({row["project"] for row in project_summary(merged)}, {"prod", "staging"})

    def test_cross_project_trust_and_clean_twin(self) -> None:
        trusting = merge_snapshots([
            _write(self.tmp, "a", "prod", [_server(1, "db", "203.0.113.5", "production", ["198.51.100.9/32"])]),
            _write(self.tmp, "b", "staging", [_server(2, "worker", "198.51.100.9", "staging")]),
        ])
        finding = next(item for item in verify_all(hunt(trusting), trusting) if item.rule_id == "HETZ-XPR-001")
        self.assertEqual(finding.status.value, "confirmed")
        self.assertEqual(finding.severity.value if finding.severity else None, "medium")
        self.assertIn("hcloud:server:2", finding.assets)
        clean = merge_snapshots([
            _write(self.tmp, "a", "prod", [_server(1, "db", "203.0.113.5", "production", ["192.0.2.44/32"])]),
            _write(self.tmp, "b", "staging", [_server(2, "worker", "198.51.100.9", "staging")]),
        ])
        self.assertFalse([item for item in hunt(clean) if item.rule_id == "HETZ-XPR-001"])

    def test_duplicate_project_is_rejected(self) -> None:
        path = _write(self.tmp, "a", "prod", [_server(1, "db", "203.0.113.5", "production")])
        with self.assertRaises(ValueError):
            merge_snapshots([path, path])

    def test_mixed_environments_in_one_project(self) -> None:
        merged = merge_snapshots([_write(self.tmp, "a", "main", [_server(1, "db", "203.0.113.5", "production"),
                                                                  _server(2, "ci", "203.0.113.6", "staging")])])
        self.assertTrue([item for item in hunt(merged) if item.rule_id == "HETZ-XPR-002"])


if __name__ == "__main__":
    unittest.main()
