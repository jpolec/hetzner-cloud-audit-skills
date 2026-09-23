"""Regressions from the second external review (public interface, latent firewalls, DNS, schemas, severity)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import jsonschema

from hetzner_security.analyzers import hunt
from hetzner_security.benchmark import generate
from hetzner_security.collectors.hcloud import _derive_edges, _minimize_rrset
from hetzner_security.models import Asset, Snapshot
from hetzner_security.policy import load_policy
from hetzner_security.schema import load_schema, validation_errors
from hetzner_security.temporal import diff_snapshots
from hetzner_security.verification import verify_all

WORLD = ["0.0.0.0/0", "::/0"]
SSH = {"direction": "in", "protocol": "tcp", "port_from": 22, "port_to": 22, "sources": WORLD}


def _server(**props: object) -> Asset:
    return Asset("hcloud:server:1", "server", "s", {"firewall_attached": True, "inbound": [SSH], "listening_ports": [22],
                                                    "host_firewall_allow_ports": [22], **props}, {}, "hcloud_api")


class PublicInterfaceTest(unittest.TestCase):
    def test_world_rule_without_public_interface_is_not_exposure(self) -> None:
        private = Snapshot(assets=[_server(public_ip=False)])
        self.assertFalse([item for item in hunt(private) if item.rule_id == "HETZ-NET-001"])
        public = Snapshot(assets=[_server(public_ip=True)])
        self.assertEqual([item.status.value for item in verify_all(hunt(public), public) if item.rule_id == "HETZ-NET-001"], ["confirmed"])

    def test_address_family_must_match(self) -> None:
        rule = {**SSH, "sources": ["0.0.0.0/0"]}
        v6_only = Snapshot(assets=[Asset("hcloud:server:1", "server", "s", {"public_ipv4": False, "public_ipv6": True, "public_ip": True,
                                                                               "firewall_attached": True, "inbound": [rule]}, {}, "hcloud_api")])
        self.assertFalse([item for item in hunt(v6_only) if item.rule_id == "HETZ-NET-001"])

    def test_collector_edges_need_a_public_interface(self) -> None:
        raw = {"server": [{"id": 1, "public_net": {}, "public_ipv4": False, "public_ipv6": False, "inbound": [SSH], "private_net": []}]}
        self.assertFalse([edge for edge in _derive_edges(raw) if edge.source == "internet"])

    def test_diff_ignores_private_servers_and_reports_closed_exposure(self) -> None:
        empty = Snapshot(assets=[Asset("hcloud:server:1", "server", "s", {"public_ip": False, "firewall_attached": True, "inbound": []}, {}, "hcloud_api")])
        self.assertFalse(diff_snapshots(empty, Snapshot(assets=[_server(public_ip=False)]))["security_regression"])
        closed = diff_snapshots(Snapshot(assets=[_server(public_ip=True)]), Snapshot(assets=[_server(public_ip=False)]))
        self.assertTrue(closed["closed_exposures"])
        self.assertFalse(closed["security_regression"])

    def test_unattached_all_ports_firewall_is_latent(self) -> None:
        firewall = Asset("hcloud:firewall:9", "firewall", "wide", {"applied_to": [], "inbound": [
            {"direction": "in", "protocol": "tcp", "port_from": None, "port_to": None, "sources": WORLD}]}, {}, "hcloud_api")
        snapshot = Snapshot(assets=[firewall])
        finding = next(item for item in verify_all(hunt(snapshot), snapshot) if item.rule_id == "HETZ-FW-001")
        self.assertEqual(finding.severity.value if finding.severity else None, "low")


class DataHygieneTest(unittest.TestCase):
    def test_dns_values_kept_only_for_address_records(self) -> None:
        txt = _minimize_rrset({"name": "_acme-challenge", "type": "TXT", "records": [{"value": "secret-token"}]})
        self.assertEqual((txt["records"], txt["record_count"]), ([], 1))
        self.assertEqual(_minimize_rrset({"type": "A", "records": [{"value": "192.0.2.1"}]})["records"][0]["value"], "192.0.2.1")

    def test_policy_rejects_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.toml"
            path.write_text('version = 1\n[ssh]\npubilc = false\n')
            with self.assertRaises(ValueError):
                load_policy(path)
            path.write_text('version = 1\n[ssh]\npublic = false\n')
            self.assertEqual(load_policy(path)["ssh"], {"public": False})


class SchemaTest(unittest.TestCase):
    def test_stdlib_validator_agrees_with_jsonschema(self) -> None:
        schema = load_schema("finding.schema.json")
        validator = jsonschema.Draft202012Validator(schema)  # finding.schema.json uses only local references
        for snapshot, _truth in generate(20260923, 20):
            for finding in verify_all(hunt(snapshot), snapshot):
                record = finding.to_dict()
                self.assertEqual(validation_errors(record, "finding.schema.json"), [], finding.rule_id)
                self.assertEqual(list(validator.iter_errors(record)), [], finding.rule_id)
        broken = {"id": "x"}
        self.assertTrue(validation_errors(broken, "finding.schema.json"))
        self.assertTrue(list(validator.iter_errors(broken)))

    def test_hypotheses_keep_potential_severity_and_deterministic_method(self) -> None:
        snapshot = Snapshot(assets=[Asset("hcloud:server:1", "server", "s", {"public_ip": True, "firewall_attached": True,
                                                                              "inbound": [SSH]}, {}, "hcloud_api")])
        finding = next(item for item in verify_all(hunt(snapshot), snapshot) if item.rule_id == "HETZ-NET-001")
        self.assertEqual(finding.status.value, "needs_validation")
        self.assertEqual(finding.metadata["potential_severity"], "high")
        self.assertNotIn("independent", finding.verification.method)


if __name__ == "__main__":
    unittest.main()
