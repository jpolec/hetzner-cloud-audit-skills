from __future__ import annotations

import unittest

from hetzner_security.graph import AttackGraph
from hetzner_security.models import Asset, Edge, Snapshot


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


if __name__ == "__main__":
    unittest.main()
