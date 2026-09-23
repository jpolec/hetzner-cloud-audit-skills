"""Regressions from the adversarial review (Robot, Object Storage, Kubernetes, merge, diff, cost, changes)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from hetzner_security.analyzers import hunt
from hetzner_security.collectors.objectstorage import public_statements
from hetzner_security.collectors.robot import robot_exposure, robot_world_ports
from hetzner_security.models import Asset, Snapshot
from hetzner_security.projects import merge_snapshots
from hetzner_security.temporal import diff_snapshots


def _ids(snapshot: Snapshot) -> set[str]:
    return {item.rule_id for item in hunt(snapshot)}


class RobotTest(unittest.TestCase):
    def test_narrow_discards_and_flags(self) -> None:
        accept22 = {"src_ip": None, "dst_port": "22", "protocol": "tcp", "action": "accept"}
        for narrow in ({"tcp_flags": "fin"}, {"src_port": "53"}, {"dst_ip": "203.0.113.9"}):
            rules = [{"src_ip": None, "dst_port": "22", "protocol": "tcp", "action": "discard", **narrow}, accept22]
            self.assertIn(22, robot_world_ports(rules), narrow)
        self.assertNotIn(22, robot_world_ports([{**accept22, "tcp_flags": "syn&ack"}]))

    def test_ipv6_rules_count_when_filtered(self) -> None:
        firewall = {"filter_ipv6": True, "rules": [{"ip_version": "ipv6", "src_ip": None, "dst_port": "22", "protocol": "tcp", "action": "accept"}]}
        self.assertIn(22, robot_exposure(firewall))


class ObjectStorageTest(unittest.TestCase):
    def test_not_principal_is_public_and_actions_case_insensitive(self) -> None:
        bucket = {"policy": {"Statement": [{"Effect": "Allow", "NotPrincipal": {"AWS": "arn:x"}, "Action": "S3:PutObject"}]}}
        self.assertEqual(len(public_statements(bucket)), 1)
        snapshot = Snapshot(assets=[Asset("s3:bucket:fsn1:b", "bucket", "b", {**bucket, "acl": [], "versioning": "Enabled"}, {}, "object_storage_api")])
        finding = next(item for item in hunt(snapshot) if item.rule_id == "HETZ-OBJ-002")
        self.assertEqual(finding.severity.value if finding.severity else None, "critical")

    def test_unread_versioning_is_no_claim(self) -> None:
        props = {"acl": [], "policy": None, "versioning": None, "reads": {"acl": True, "policy": True, "versioning": False}}
        self.assertNotIn("HETZ-OBJ-003", _ids(Snapshot(assets=[Asset("s3:bucket:fsn1:b", "bucket", "b", props, {}, "object_storage_api")])))


class KubernetesAndChangesTest(unittest.TestCase):
    def test_private_node_port_is_not_exposed(self) -> None:
        node = Asset("hcloud:server:1", "server", "n1", {"public_ip": False, "firewall_attached": True, "k8s": {"role": "worker"},
                     "inbound": [{"direction": "in", "protocol": "tcp", "port_from": 30000, "port_to": 32767, "sources": ["0.0.0.0/0"]}]}, {}, "hcloud_api")
        service = Asset("k8s:service:c:ns/web", "k8s_service", "ns/web", {"type": "NodePort", "ports": [{"node_port": 30080, "protocol": "tcp"}]}, {}, "kubernetes")
        self.assertNotIn("HETZ-K8S-001", _ids(Snapshot(assets=[node, service])))

    def test_protection_turned_on_is_not_reported(self) -> None:
        server = Asset("hcloud:server:1", "server", "web", {"protection": {"delete": True}, "backup_enabled": False}, {}, "hcloud_api")
        action = {"type": "provider_action", "command": "change_protection", "started": "2026-09-20T00:00:00Z", "asset_ids": [server.id]}
        self.assertNotIn("HETZ-CHG-001", _ids(Snapshot(assets=[server], signals=[action])))


class MergeAndDiffTest(unittest.TestCase):
    def _write(self, tmp: Path, name: str, project: str, assets: list[Asset], coverage: dict[str, object] | None = None) -> Path:
        path = tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(Snapshot(assets=assets, metadata={"project": project, "coverage": coverage or {}}).to_dict()))
        return path

    def test_shared_system_images_and_duplicate_names(self) -> None:
        image = Asset("hcloud:image:1", "image", "ubuntu-24.04", {"type": "system"}, {}, "hcloud_api")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            merged = merge_snapshots([self._write(root, "a.json", "prod", [image]), self._write(root, "b.json", "staging", [image])])
            self.assertEqual(sum(1 for asset in merged.assets if asset.type == "image"), 1)
            with self.assertRaises(ValueError):
                merge_snapshots([self._write(root, "p/snapshot.json", "", [image]), self._write(root, "s/snapshot.json", "", [])])

    def test_diff_does_not_verify_savings_across_collection_gaps(self) -> None:
        pricing = Asset("hcloud:pricing:current", "pricing", "p", {"currency": "EUR"}, {}, "hcloud_api")
        before = Snapshot(assets=[pricing], metadata={"coverage": {"server": {"status": "collected"}}})
        after = Snapshot(assets=[pricing], metadata={"coverage": {"server": {"status": "failed"}}})
        self.assertIsNone(diff_snapshots(before, after)["cost"]["verified_monthly_savings"])


if __name__ == "__main__":
    unittest.main()
