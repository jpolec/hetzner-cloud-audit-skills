from __future__ import annotations

import unittest

from hetzner_security.graph import AttackGraph
from hetzner_security.models import Asset, Edge, Evidence, Snapshot


class AttackGraphTest(unittest.TestCase):
    def test_bounded_reachability_and_cycles(self) -> None:
        snapshot = Snapshot(
            assets=[Asset("a", "server", "a"), Asset("b", "network", "b"), Asset("c", "postgres", "c")],
            edges=[
                Edge("a", "b", "attached"),
                Edge("b", "a", "contains"),
                Edge("b", "c", "allows", "tcp", 5432),
            ],
        )
        graph = AttackGraph(snapshot)
        self.assertTrue(graph.reachable("a", "c", protocol="tcp", port=5432))
        self.assertFalse(graph.reachable("a", "c", protocol="tcp", port=6379))

    def test_public_interface_does_not_prove_service_port_is_allowed(self) -> None:
        snapshot = Snapshot(
            assets=[Asset("server:db", "server", "db")],
            edges=[Edge("internet", "server:db", "public_interface")],
        )
        graph = AttackGraph(snapshot)
        self.assertFalse(graph.reachable("internet", "server:db", protocol="tcp", port=5432))

    def test_firewall_range_is_checked_for_requested_port(self) -> None:
        evidence = Evidence(
            "fixture",
            "firewall_rule",
            "server:web",
            {"port_from": 80, "port_to": 443},
        )
        snapshot = Snapshot(
            assets=[Asset("server:web", "server", "web")],
            edges=[Edge("internet", "server:web", "allows", "tcp", None, (evidence,))],
        )
        graph = AttackGraph(snapshot)
        self.assertTrue(graph.reachable("internet", "server:web", protocol="tcp", port=443))
        self.assertFalse(graph.reachable("internet", "server:web", protocol="tcp", port=5432))


if __name__ == "__main__":
    unittest.main()
