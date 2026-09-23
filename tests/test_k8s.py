from __future__ import annotations

import unittest
from pathlib import Path

from hetzner_security.analyzers import hunt
from hetzner_security.graph import AttackGraph
from hetzner_security.k8s import apply_k8s, load_k8s
from hetzner_security.models import Asset, Edge, Evidence, Snapshot
from hetzner_security.verification import verify_all

FIXTURE = Path(__file__).parent / "fixtures" / "k8s" / "cluster.json"
WORLD = ["0.0.0.0/0", "::/0"]


def _server(sid: int, name: str, node_ports: list[str]) -> Asset:
    rules = [{"direction": "in", "protocol": "tcp", "port_from": 443, "port_to": 443, "sources": WORLD},
             {"direction": "in", "protocol": "tcp", "port_from": 30000, "port_to": 32767, "sources": node_ports}]
    return Asset(f"hcloud:server:{sid}", "server", name, {"public_ip": True, "firewall_attached": True, "inbound": rules},
                 {"environment": "production"}, "hcloud_api")


def _snapshot(node_ports: list[str]) -> Snapshot:
    servers = [_server(201, "cp-1", ["10.0.0.0/16"]), _server(202, "worker-1", node_ports), _server(203, "worker-2", ["10.0.0.0/16"])]
    # The Internet edge the collector derives from worker-1's firewall rule.
    edges = [Edge("internet", "hcloud:server:202", "allows", "tcp", None,
                  (Evidence("hcloud_api", "firewall_rule", "hcloud:server:202", {"port_from": 30000, "port_to": 32767}),))] if node_ports == WORLD else []
    return apply_k8s(Snapshot(assets=servers, edges=edges), load_k8s(FIXTURE), "shop-cluster")


class KubernetesTest(unittest.TestCase):
    def test_nodes_map_to_servers_by_provider_id(self) -> None:
        snapshot = _snapshot(["10.0.0.0/16"])
        meta = snapshot.metadata["kubernetes"]
        self.assertEqual(meta["unmatched_nodes"], [])
        self.assertIn("Hetzner CCM", meta["integrations"])
        roles = {asset.name: asset.properties["k8s"]["role"] for asset in snapshot.assets if asset.type == "server"}
        self.assertEqual(roles["cp-1"], "control-plane")

    def test_world_open_node_ports(self) -> None:
        snapshot = _snapshot(WORLD)
        findings = [item for item in verify_all(hunt(snapshot), snapshot) if item.rule_id == "HETZ-K8S-001"]
        severities = {item.assets[0].rsplit("/", 1)[-1]: item.severity.value if item.severity else None for item in findings}
        self.assertEqual(severities, {"web-nodeport": "high", "web-lb": "medium"})
        self.assertTrue(AttackGraph(snapshot).reachable("internet", "k8s:service:shop-cluster:shop/web-nodeport", protocol="tcp", port=30080))

    def test_private_node_ports_are_clean(self) -> None:
        snapshot = _snapshot(["10.0.0.0/16"])
        self.assertFalse([item for item in hunt(snapshot) if item.rule_id == "HETZ-K8S-001"])

    def test_workload_breakout_system_vs_application(self) -> None:
        snapshot = _snapshot(["10.0.0.0/16"])
        findings = {item.assets[0].split(":", 3)[-1]: item for item in verify_all(hunt(snapshot), snapshot) if item.rule_id == "HETZ-K8S-002"}
        self.assertEqual(findings["kube-system/DaemonSet/cilium"].status.value, "needs_validation")
        builder = findings["shop/Deployment/builder"]
        self.assertEqual(builder.status.value, "confirmed")
        self.assertEqual(builder.severity.value if builder.severity else None, "high")
        self.assertNotIn("shop/Deployment/web", findings)


if __name__ == "__main__":
    unittest.main()
