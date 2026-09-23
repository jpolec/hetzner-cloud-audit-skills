from __future__ import annotations

import random
import unittest

from hetzner_security.flows import PortSet, asset_exposure, exposure_growth, snapshot_exposure
from hetzner_security.models import Asset, Snapshot
from hetzner_security.temporal import diff_snapshots

UNIVERSE = 400  # small port universe keeps the brute-force oracle fast


def _random_set(rng: random.Random) -> PortSet:
    spans = []
    for _ in range(rng.randint(0, 5)):
        a = rng.randint(0, UNIVERSE)
        spans.append((a, rng.randint(a, min(UNIVERSE, a + rng.randint(0, 60)))))
    return PortSet.of(spans)


def _members(ports: PortSet) -> set[int]:
    return {port for port in range(UNIVERSE + 1) if port in ports}


class PortSetPropertyTest(unittest.TestCase):
    def test_algebra_matches_brute_force(self) -> None:
        rng = random.Random(20260923)
        for _ in range(300):
            a, b = _random_set(rng), _random_set(rng)
            self.assertEqual(_members(a.union(b)), _members(a) | _members(b))
            self.assertEqual(_members(a.intersection(b)), _members(a) & _members(b))
            self.assertEqual(_members(a.difference(b)), _members(a) - _members(b))
            self.assertEqual(a.size(), len(_members(a)))
            # normalized: sorted, non-overlapping, non-adjacent ranges
            for (_s1, e1), (s2, _e2) in zip(a.ranges, a.ranges[1:], strict=False):
                self.assertLess(e1 + 1, s2)


def _server(name: str, rules: list[dict[str, object]]) -> Asset:
    return Asset(f"hcloud:server:{name}", "server", name, {"public_ip": True, "inbound": rules}, source="hcloud_api")


def _rule(first: int | None, last: int | None, sources: list[str], protocol: str = "tcp") -> dict[str, object]:
    return {"protocol": protocol, "port_from": first, "port_to": last, "sources": sources}


class SemanticDiffTest(unittest.TestCase):
    def test_widening_a_range_is_a_regression(self) -> None:
        before = Snapshot(assets=[_server("web", [_rule(80, 443, ["0.0.0.0/0"])])])
        after = Snapshot(assets=[_server("web", [_rule(80, 8443, ["0.0.0.0/0"])])])
        diff = diff_snapshots(before, after)
        self.assertTrue(diff["security_regression"])
        self.assertEqual(diff["new_exposures"][0]["ports"], "444-8443")

    def test_new_public_ip_behind_deny_all_is_not_a_regression(self) -> None:
        before = Snapshot(assets=[])
        after = Snapshot(assets=[_server("db", [_rule(5432, 5432, ["10.0.0.0/16"])])])
        self.assertFalse(diff_snapshots(before, after)["security_regression"])

    def test_ipv6_only_opening_is_reported_per_family(self) -> None:
        before = Snapshot(assets=[_server("api", [_rule(443, 443, ["0.0.0.0/0"])])])
        after = Snapshot(assets=[_server("api", [_rule(443, 443, ["0.0.0.0/0"]), _rule(22, 22, ["::/0"])])])
        growth = diff_snapshots(before, after)["new_exposures"]
        self.assertEqual([(item["family"], item["ports"]) for item in growth], [("ipv6", "22")])

    def test_narrowing_and_allowlist_are_not_regressions(self) -> None:
        before = Snapshot(assets=[_server("api", [_rule(1, 65535, ["0.0.0.0/0"])])])
        after = Snapshot(assets=[_server("api", [_rule(443, 443, ["0.0.0.0/0"]), _rule(22, 22, ["203.0.113.7/32"])])])
        diff = diff_snapshots(before, after)
        self.assertFalse(diff["security_regression"])
        self.assertEqual(diff["new_allowlisted_flows"][0]["ports"], "22")

    def test_random_rule_sets_growth_equals_set_difference(self) -> None:
        rng = random.Random(7)
        for _ in range(150):
            def rules() -> list[dict[str, object]]:
                output = []
                for _ in range(rng.randint(0, 4)):
                    a = rng.randint(1, 300)
                    output.append(_rule(a, a + rng.randint(0, 40), [rng.choice(["0.0.0.0/0", "::/0", "10.0.0.0/8"])]))
                return output

            before, after = Snapshot(assets=[_server("s", rules())]), Snapshot(assets=[_server("s", rules())])
            growth = exposure_growth(snapshot_exposure(before), snapshot_exposure(after))
            for family, world in (("ipv4", "0.0.0.0/0"), ("ipv6", "::/0")):
                def world_ports(snapshot: Snapshot, family: str = family, world: str = world) -> set[int]:
                    return {
                        port
                        for rule in snapshot.assets[0].properties["inbound"]
                        if world in rule["sources"]
                        for port in range(int(rule["port_from"]), int(rule["port_to"]) + 1)
                    }
                expected = world_ports(after) - world_ports(before)
                reported = set()
                for item in growth:
                    if item["family"] == family and item["source_class"] == "world":
                        for part in item["ports"].split(", "):
                            a, _, b = part.partition("-")
                            reported |= set(range(int(a), int(b or a) + 1))
                self.assertEqual(reported, expected)

    def test_load_balancer_services_are_exposure(self) -> None:
        lb = Asset("hcloud:load_balancer:1", "load_balancer", "lb", {"public_net": {"enabled": True}, "services": [{"listen_port": 443}]})
        self.assertIn(443, asset_exposure(lb)[("ipv4", "tcp", "world")])


if __name__ == "__main__":
    unittest.main()
