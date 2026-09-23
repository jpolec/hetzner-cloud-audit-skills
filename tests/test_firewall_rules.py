from __future__ import annotations

import json
import unittest

from hetzner_security.analyzers import hunt
from hetzner_security.findings import render_json, render_sarif
from hetzner_security.models import Asset, Snapshot
from hetzner_security.verification import verify_all


def _rule(protocol: str, first: int | None, last: int | None, sources: list[str]) -> dict[str, object]:
    return {"direction": "in", "protocol": protocol, "port_from": first, "port_to": last, "sources": sources}


def _firewall(name: str, rules: list[dict[str, object]], applied: list[dict[str, object]] | None = None) -> Asset:
    return Asset(
        f"hcloud:firewall:{name}", "firewall", name,
        {"inbound": rules, "applied_to": [{"type": "server", "server": {"id": 1}}] if applied is None else applied},
        source="hcloud_api",
    )


def _server(name: str, rules: list[dict[str, object]]) -> Asset:
    return Asset(f"hcloud:server:{name}", "server", name, {"public_ip": True, "firewall_attached": True, "inbound": rules}, source="hcloud_api")


def _ids(snapshot: Snapshot) -> list[str]:
    return sorted(finding.rule_id for finding in verify_all(hunt(snapshot), snapshot))


class FirewallQualityTest(unittest.TestCase):
    def test_all_ports_open_is_one_confirmed_finding_not_one_per_service(self) -> None:
        world_all = _rule("tcp", None, None, ["0.0.0.0/0", "::/0"])
        snapshot = Snapshot(assets=[_firewall("wide", [world_all]), _server("app", [world_all])])
        findings = verify_all(hunt(snapshot), snapshot)
        fw = [item for item in findings if item.rule_id == "HETZ-FW-001"]
        self.assertEqual(len(fw), 1)
        self.assertEqual(fw[0].status.value, "confirmed")
        self.assertFalse([item for item in findings if item.rule_id.startswith("HETZ-NET-00") and item.rule_id != "HETZ-NET-005"])

    def test_clean_twin_has_no_firewall_findings(self) -> None:
        rules = [_rule("tcp", 443, 443, ["0.0.0.0/0", "::/0"]), _rule("tcp", 22, 22, ["100.64.0.0/10"])]
        snapshot = Snapshot(assets=[_firewall("web", rules), _server("web", rules)])
        self.assertFalse([rule for rule in _ids(snapshot) if rule.startswith("HETZ-FW-") or rule.startswith("HETZ-NET-")])

    def test_ipv6_only_exposure_duplicates_and_unattached(self) -> None:
        rules = [_rule("tcp", 8080, 8080, ["::/0"]), _rule("tcp", 8080, 8080, ["::/0"])]
        ids = _ids(Snapshot(assets=[_firewall("v6", rules), _firewall("orphan", [], applied=[])]))
        self.assertIn("HETZ-FW-003", ids)
        self.assertIn("HETZ-FW-004", ids)
        self.assertIn("HETZ-FW-002", ids)

    def test_label_selector_matching_nothing_counts_as_unattached(self) -> None:
        selector = [{"type": "label_selector", "label_selector": {"selector": "role=db"}, "applied_to_resources": []}]
        self.assertIn("HETZ-FW-002", _ids(Snapshot(assets=[_firewall("sel", [], applied=selector)])))
        matched = [{**selector[0], "applied_to_resources": [{"type": "server", "server": {"id": 3}}]}]
        self.assertNotIn("HETZ-FW-002", _ids(Snapshot(assets=[_firewall("sel", [], applied=matched)])))


class SensitiveServicesTest(unittest.TestCase):
    def _titles(self, rule: dict[str, object]) -> list[str]:
        snapshot = Snapshot(assets=[_server("host", [rule])])
        return [item.title for item in hunt(snapshot) if item.rule_id == "HETZ-NET-002"]

    def test_new_tcp_udp_and_range_services(self) -> None:
        self.assertIn("MySQL/MariaDB reachable from the public internet", self._titles(_rule("tcp", 3306, 3306, ["0.0.0.0/0"])))
        self.assertIn("Memcached (UDP amplification) reachable from the public internet", self._titles(_rule("udp", 11211, 11211, ["::/0"])))
        self.assertIn("Kubernetes NodePort range reachable from the public internet", self._titles(_rule("tcp", 31000, 31010, ["0.0.0.0/0"])))
        self.assertEqual(self._titles(_rule("udp", 3306, 3306, ["0.0.0.0/0"])), [])  # protocol must match
        self.assertEqual(self._titles(_rule("tcp", 8443, 8443, ["0.0.0.0/0"])), [])  # public web port is not "sensitive"


class SerializationTest(unittest.TestCase):
    def test_every_finding_serializes_to_json_and_sarif(self) -> None:
        cf = _server("fronted", [_rule("tcp", 443, 443, ["173.245.48.0/20"])])
        direct = _server("direct", [_rule("tcp", 443, 443, ["0.0.0.0/0"]), _rule("tcp", None, None, ["0.0.0.0/0"])])
        snapshot = Snapshot(assets=[cf, direct, _firewall("wide", [_rule("tcp", None, None, ["0.0.0.0/0"])]), _firewall("orphan", [], applied=[])])
        findings = verify_all(hunt(snapshot), snapshot)
        self.assertTrue({"HETZ-NET-006", "HETZ-FW-001", "HETZ-FW-002"} <= {item.rule_id for item in findings})
        json.loads(render_json(findings))
        json.loads(render_sarif(findings))


if __name__ == "__main__":
    unittest.main()
