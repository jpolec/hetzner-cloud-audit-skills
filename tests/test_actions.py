from __future__ import annotations

import unittest

from hetzner_security.actions import (
    build_actions,
    cost_insights,
    evidence_level,
    replacement_candidate,
)
from hetzner_security.analyzers import hunt
from hetzner_security.models import Asset, Snapshot
from hetzner_security.verification import verify_all


def _type(name: str, price: float, *, deprecated: bool = False, available: bool = True, arch: str = "x86", category: str = "cost_optimized") -> Asset:
    return Asset(
        f"hcloud:server_type:{name}",
        "server_type",
        name,
        {
            "name": name, "cores": 2, "memory": 4, "architecture": arch, "cpu_type": "shared", "category": category,
            "deprecated": deprecated,
            "locations": [{"name": "hel1", "available": available}],
            "prices": [{"location": "hel1", "price_monthly": {"net": str(price)}}],
        },
        source="hcloud_api",
    )


class ActionsTest(unittest.TestCase):
    def test_replacement_reports_unavailable_successor_and_arm_alternative(self) -> None:
        current = {**_type("cx22", 4.49, deprecated=True).properties}
        server = Asset("hcloud:server:1", "server", "legacy", {"server_type": current, "location": {"name": "hel1"}}, source="hcloud_api")
        snapshot = Snapshot(assets=[server, _type("cx23", 4.99, available=False), _type("cpx22", 19.49, category="regular_purpose"), _type("cax11", 5.99, arch="arm")])
        candidate = replacement_candidate(snapshot, server)
        if candidate is None:
            self.fail("expected a replacement candidate")
        self.assertEqual(candidate["server_type"], "cpx22")
        self.assertEqual(candidate["family_unavailable"], "cx23")
        self.assertEqual(candidate["arm"]["server_type"], "cax11")
        self.assertAlmostEqual(candidate["delta"], 15.0)

    def test_cost_insights_separate_waste_from_telemetry_bound_opportunities(self) -> None:
        cost = {
            "servers": [
                {"asset_id": "a", "name": "big", "monthly_net": 80, "components_net": {"server": 35, "volumes": 45}},
                {"asset_id": "b", "name": "small", "monthly_net": 20, "components_net": {"server": 18, "volumes": 2}},
            ],
            "recommendations": [
                {"rule_id": "HETZ-COST-004", "assets": ["vol"], "estimated_savings": {"monthly": 2.86}},
                {"rule_id": "HETZ-COST-002", "assets": ["a"], "estimated_savings": {"monthly": 10}},
                {"rule_id": "HETZ-COST-003", "assets": ["a"], "estimated_savings": {"monthly": 25}},
            ],
        }
        insights = cost_insights(cost)
        self.assertEqual(insights["waste_monthly"], 2.86)
        self.assertEqual(insights["opportunities"], 1)
        self.assertEqual(insights["opportunities_monthly"], 25)  # alternatives for one asset are not summed
        self.assertEqual([item["name"] for item in insights["storage_heavy"]], ["big"])
        self.assertAlmostEqual(insights["top3_share"], 1.0)

    def test_actions_rank_exposure_before_hygiene_with_evidence_levels(self) -> None:
        web = Asset(
            "hcloud:server:1", "server", "direct-web",
            {"public_ip": True, "firewall_attached": True, "inbound": [{"protocol": "tcp", "port_from": 443, "port_to": 443, "sources": ["0.0.0.0/0"]}]},
            source="hcloud_api",
        )
        fronted = Asset(
            "hcloud:server:2", "server", "fronted-web",
            {"public_ip": True, "firewall_attached": True, "inbound": [{"protocol": "tcp", "port_from": 443, "port_to": 443, "sources": ["173.245.48.0/20"]}]},
            {"project": "web"}, "hcloud_api",
        )
        snapshot = Snapshot(assets=[web, fronted])
        findings = verify_all(hunt(snapshot), snapshot)
        actions = build_actions(snapshot, findings)
        self.assertTrue(actions[0]["title"].startswith("Restrict direct-web web ports"))
        self.assertEqual(actions[0]["evidence_level"], "MEDIUM")
        self.assertEqual(actions[-1]["category"], "hygiene")
        self.assertEqual([item["rank"] for item in actions], list(range(1, len(actions) + 1)))
        labels = next(item for item in findings if item.rule_id == "HETZ-GOV-002")
        self.assertEqual(evidence_level(labels)[0], "HIGH")


class GroupedActionsTest(unittest.TestCase):
    def test_many_findings_of_one_rule_become_one_action(self) -> None:
        records = [
            Asset(f"hcloud:dns_rrset:r{index}", "dns_rrset", f"r{index}.example.com A", {"type": "A", "records": [{"value": f"198.51.100.{index}"}]}, source="hcloud_api")
            for index in range(1, 8)
        ]
        snapshot = Snapshot(assets=records)
        actions = [item for item in build_actions(snapshot, verify_all(hunt(snapshot), snapshot)) if "HETZ-DNS-001" in item["rules"]]
        self.assertEqual(len(actions), 1)
        self.assertIn("(7 resources)", actions[0]["title"])


if __name__ == "__main__":
    unittest.main()
