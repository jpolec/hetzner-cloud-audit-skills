from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hetzner_security.analyzers import hunt
from hetzner_security.collectors.hcloud import _normalize_resources
from hetzner_security.findings.summary import build_summary
from hetzner_security.flows import egress_summary
from hetzner_security.models import Asset, Snapshot
from hetzner_security.policy import apply_policy, load_policy
from hetzner_security.temporal import diff_snapshots
from hetzner_security.verification import verify_all


def _server(role: str, outbound: list[dict[str, object]], **props: object) -> Asset:
    return Asset(f"hcloud:server:{role}", "server", f"{role}-1", {"public_ip": True, "firewall_attached": True, "inbound": [],
                                                                  "outbound": outbound, **props}, {"role": role}, "hcloud_api")


HTTPS_OUT = {"direction": "out", "protocol": "tcp", "port_from": 443, "port_to": 443, "destinations": ["0.0.0.0/0", "::/0"]}


class EgressTest(unittest.TestCase):
    def test_hetzner_semantics(self) -> None:
        self.assertEqual(egress_summary(_server("db", []))["state"], "unrestricted")
        limited = egress_summary(_server("db", [HTTPS_OUT]))
        self.assertEqual((limited["state"], limited["ports"]["ipv4/tcp"]), ("limited", "443"))
        self.assertEqual(egress_summary(_server("db", [], public_ip=False))["state"], "none")

    def test_collector_keeps_outbound_rules(self) -> None:
        raw = {"firewall": [{"id": 1, "rules": [{"direction": "out", "protocol": "tcp", "port": "443", "destination_ips": ["0.0.0.0/0"]}]}],
               "server": [{"id": 5, "public_net": {"ipv4": {"ip": "203.0.113.5"}, "firewalls": [{"id": 1}]}, "labels": {}}]}
        server = _normalize_resources(raw)["server"][0]
        self.assertEqual(server["outbound"][0]["destinations"], ["0.0.0.0/0"])

    def test_policy_violation_needs_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.toml"
            path.write_text('version = 1\n[roles.db]\ninternet_egress = false\n[roles.app]\ninternet_egress = ["tcp/443"]\n')
            policy = load_policy(path)
        snapshot = apply_policy(Snapshot(assets=[_server("db", []), _server("app", [HTTPS_OUT])]), policy, source="policy.toml")
        findings = [item for item in verify_all(hunt(snapshot), snapshot) if item.rule_id == "HETZ-EGR-001"]
        self.assertEqual([item.assets[0] for item in findings], ["hcloud:server:db"])  # app stays within tcp/443
        self.assertEqual(findings[0].status.value, "needs_validation")
        self.assertEqual(findings[0].metadata["potential_severity"], "high")
        self.assertEqual(build_summary(snapshot, findings)["egress"]["sensitive_unrestricted"], ["db-1"])

    def test_new_egress_is_a_strict_regression(self) -> None:
        before = Snapshot(assets=[_server("db", [HTTPS_OUT])])
        after = Snapshot(assets=[_server("db", [])])
        self.assertTrue(diff_snapshots(before, after, "strict")["new_egress"])
        self.assertTrue(diff_snapshots(before, after, "strict")["security_regression"])
        self.assertFalse(diff_snapshots(before, after, "broad")["security_regression"])


if __name__ == "__main__":
    unittest.main()
