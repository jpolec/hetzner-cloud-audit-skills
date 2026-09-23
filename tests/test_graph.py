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

    def test_public_interface_is_not_a_pivot_into_private_network(self) -> None:
        snapshot = Snapshot(
            assets=[Asset("server:app", "server", "app"), Asset("net", "network", "net"), Asset("server:db", "server", "db")],
            edges=[
                Edge("internet", "server:app", "public_interface"),
                Edge("server:app", "net", "attached_to"),
                Edge("net", "server:db", "allows", "tcp", None),
            ],
        )
        graph = AttackGraph(snapshot)
        self.assertFalse(graph.reachable("internet", "server:db", protocol="tcp", port=5432))
        self.assertTrue(graph.reachable("server:app", "server:db", protocol="tcp", port=5432))

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


class TransitionKindsTest(unittest.TestCase):
    def test_lb_forwarding_is_direct_and_private_pivot_is_not(self) -> None:
        from hetzner_security.graph import AttackGraph
        from hetzner_security.models import Asset, Edge, Snapshot

        assets = [Asset("lb", "load_balancer", "lb"), Asset("web", "server", "web"), Asset("net", "network", "net"),
                  Asset("db", "server", "db")]
        edges = [Edge("internet", "lb", "allows", "tcp", 443), Edge("lb", "web", "allows", "tcp", 8080),
                 Edge("web", "net", "attached_to"), Edge("net", "db", "allows", "tcp", 5432)]
        graph = AttackGraph(Snapshot(assets=assets, edges=edges))
        to_web = graph.explain_path("internet", "web", protocol="tcp", port=8080)
        self.assertEqual([item["kind"] for item in to_web["transitions"]], ["FILTER", "FORWARD"])
        self.assertTrue(to_web["reachability"]["direct"])
        to_db = graph.explain_path("internet", "db", protocol="tcp", port=5432)
        self.assertIn("PIVOT", [item["kind"] for item in to_db["transitions"]])
        self.assertFalse(to_db["reachability"]["direct"])
