"""Regressions from the fourth review: diff buckets, pivot semantics, path choice, scale."""

from __future__ import annotations

import ipaddress
import random
import unittest

from hetzner_security.flows import asset_flowspace, space_minus, space_minus_slabs
from hetzner_security.graph import AttackGraph
from hetzner_security.models import Asset, Edge, Snapshot
from hetzner_security.provider_ranges import EDGE_RANGES
from hetzner_security.temporal import diff_snapshots


def _server(rules: list[dict[str, object]]) -> Asset:
    return Asset("hcloud:server:1", "server", "web", {"public_ip": True, "firewall_attached": True, "inbound": rules}, {}, "hcloud_api")


def _rule(port: int, sources: list[str], last: int | None = None) -> dict[str, object]:
    return {"protocol": "tcp", "port_from": port, "port_to": last or port, "sources": sources}


class DiffBucketsTest(unittest.TestCase):
    def test_new_edge_proxy_ingress_is_reported(self) -> None:
        cloudflare = [value for value in EDGE_RANGES["cloudflare"]["ranges"] if ":" not in value][:3]
        diff = diff_snapshots(Snapshot(assets=[_server([])]), Snapshot(assets=[_server([_rule(443, cloudflare)])]), "strict")
        self.assertTrue(diff["security_regression"])
        self.assertEqual(diff["new_trusted_flows"][0]["source_class"], "edge:Cloudflare")
        self.assertEqual(len(diff["new_ingress_flows"]), len(diff["new_exposures"]) + len(diff["new_trusted_flows"]))
        self.assertIn("edge:Cloudflare", "\n".join(__import__("hetzner_security.temporal", fromlist=["x"]).render_diff_markdown(diff).splitlines()))


class PivotSemanticsTest(unittest.TestCase):
    def _graph(self, direct_web_to_db: bool = False) -> AttackGraph:
        assets = [Asset("web", "server", "web"), Asset("net", "network", "net"), Asset("db", "server", "db"), Asset("jump", "server", "jump")]
        edges = [Edge("internet", "web", "allows", "tcp", 443), Edge("web", "net", "attached_to"), Edge("net", "db", "allows", "tcp", 5432)]
        if direct_web_to_db:
            # A longer path with no pivot: internet -> jump (forward-like LB is not modeled here, so use allows) ...
            edges += [Edge("internet", "jump", "allows", "tcp", 5432)]
        return AttackGraph(Snapshot(assets=assets, edges=edges))

    def test_source_already_controlled_is_not_a_pivot(self) -> None:
        from_web = self._graph().explain_path("web", "db", protocol="tcp", port=5432)
        self.assertEqual(from_web["reachability"]["pivots_required"], 0)
        self.assertTrue(from_web["reachability"]["direct"])
        from_internet = self._graph().explain_path("internet", "db", protocol="tcp", port=5432)
        self.assertEqual(from_internet["reachability"]["pivots_required"], 1)

    def test_path_choice_prefers_fewer_pivots(self) -> None:
        assets = [Asset(name, "server", name) for name in ("web", "db", "lb-host")] + [Asset("net", "network", "net"), Asset("lb", "load_balancer", "lb")]
        edges = [
            Edge("internet", "web", "allows", "tcp", 443), Edge("web", "net", "attached_to"), Edge("net", "db", "allows", "tcp", 5432),  # 3 hops, 1 pivot
            Edge("internet", "lb", "allows", "tcp", 5432), Edge("lb", "lb-host", "allows", "tcp", 5432),
            Edge("lb-host", "db", "allows", "tcp", 5432),  # 3 hops, no attached_to pivot
        ]
        result = AttackGraph(Snapshot(assets=assets, edges=edges)).explain_path("internet", "db", protocol="tcp", port=5432)
        self.assertEqual(result["reachability"]["pivots_required"], 0)

    def test_complete_pivot_path_is_reachable_after_pivot(self) -> None:
        db = Asset("db", "postgres", "db", {"host_firewall_allows_source": True, "listening_ports": [5432]})
        assets = [Asset("web", "server", "web"), Asset("net", "network", "net"), db]
        edges = [Edge("internet", "web", "allows", "tcp", 443), Edge("web", "net", "attached_to"), Edge("net", "db", "allows", "tcp", 5432)]
        result = AttackGraph(Snapshot(assets=assets, edges=edges)).explain_path("internet", "db", protocol="tcp", port=5432)
        self.assertEqual(result["result"], "reachable_after_pivot")


class ScaleTest(unittest.TestCase):
    def test_overlapping_rules_are_exact_and_linear(self) -> None:
        """Correctness and complexity only; wall-clock timing lives in scripts/benchmark_flowspace.py."""
        rng = random.Random(3)
        base = int(ipaddress.ip_address("198.51.100.0"))

        def rules() -> list[tuple[int, int, int, int]]:
            output = []
            for _ in range(500):  # one firewall's worth of rules, heavily overlapping checkerboard
                start = base + rng.randint(0, 4000)
                port = rng.randint(1, 60000)
                output.append((start, start + rng.randint(0, 512), port, port + rng.randint(0, 200)))
            return output

        after, before = rules(), rules()
        slabs = space_minus_slabs(after, before)
        self.assertLessEqual(len(slabs), 2 * (len(after) + len(before)))  # linear in the number of rules
        # Spot-check exactness on random points.
        for _ in range(300):
            ip, port = base + rng.randint(0, 4600), rng.randint(1, 60300)
            def inside(rects: list[tuple[int, int, int, int]], ip: int = ip, port: int = port) -> bool:
                return any(a <= ip <= b and c <= port <= d for a, b, c, d in rects)

            in_result = any(first <= ip <= last and port in ports for first, last, ports in slabs)
            self.assertEqual(in_result, inside(after) and not inside(before))

    def test_ipv6_mixture(self) -> None:
        rules = [_rule(443, [f"2001:db8:{index:x}::/64"]) for index in range(200)] + [_rule(22, ["2001:db8::/32"])]
        space = asset_flowspace(_server(rules))
        self.assertTrue(space_minus(space[("ipv6", "tcp")], []))


if __name__ == "__main__":
    unittest.main()
