from __future__ import annotations

import unittest

from hetzner_security.collectors.hcloud import _derive_edges
from hetzner_security.collectors.robot import apply_robot
from hetzner_security.graph import AttackGraph
from hetzner_security.models import Asset, Snapshot
from hetzner_security.topology import build_topology


def _raw() -> dict[str, list[dict[str, object]]]:
    return {
        "server": [{"id": 7, "public_net": {"ipv4": {"ip": "203.0.113.7"}}, "private_net": [{"network": 1, "ip": "10.0.1.7"}], "inbound": []}],
        "load_balancer": [{"id": 80, "public_net": {"enabled": True},
                           "services": [{"protocol": "https", "listen_port": 443, "destination_port": 8080}],
                           "targets": [{"type": "ip", "ip": {"ip": "10.0.1.7"}},
                                       {"type": "ip", "ip": {"ip": "198.51.100.40"}},
                                       {"type": "ip", "ip": {"ip": "192.0.2.99"}}]}],
    }


class LoadBalancerIpTargetTest(unittest.TestCase):
    def test_ip_targets_resolve_or_stay_explicit(self) -> None:
        targets = {edge.target for edge in _derive_edges(_raw()) if edge.source == "hcloud:load_balancer:80"}
        self.assertEqual(targets, {"hcloud:server:7", "endpoint:ip:198.51.100.40", "endpoint:ip:192.0.2.99"})

    def test_robot_server_behind_cloud_lb(self) -> None:
        edges = _derive_edges(_raw())
        assets = [
            Asset("hcloud:load_balancer:80", "load_balancer", "edge-lb", {"public_net": {"enabled": True}, "services": [], "targets": []}, {}, "hcloud_api"),
            Asset("endpoint:ip:198.51.100.40", "endpoint", "198.51.100.40", {"ip": "198.51.100.40"}, {}, "hcloud_api"),
            Asset("endpoint:ip:192.0.2.99", "endpoint", "192.0.2.99", {"ip": "192.0.2.99"}, {}, "hcloud_api"),
        ]
        snapshot = apply_robot(Snapshot(assets=assets, edges=edges), {"server": [{"server": {
            "server_number": 5101, "server_name": "db-dedicated", "server_ip": "198.51.100.40", "ip": ["198.51.100.40"]}}], "firewall": {}})
        graph = AttackGraph(snapshot)
        self.assertTrue(graph.reachable("internet", "robot:server:5101", protocol="tcp", port=8080))
        self.assertNotIn("endpoint:ip:198.51.100.40", {asset.id for asset in snapshot.assets})
        self.assertIn("endpoint:ip:192.0.2.99", {asset.id for asset in snapshot.assets})  # unknown host kept, not dropped
        lb = build_topology(snapshot)["load_balancers"][0]
        self.assertIn("db-dedicated", lb["targets"])
        self.assertIn("192.0.2.99", lb["targets"])


if __name__ == "__main__":
    unittest.main()
