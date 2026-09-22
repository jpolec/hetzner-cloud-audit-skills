from __future__ import annotations

import unittest

from hetzner_security.analyzers import hunt
from hetzner_security.models import Asset, Edge, Evidence, Snapshot


class FalsePositiveTest(unittest.TestCase):
    def test_ssh_open_to_specific_vpn_is_not_public_exposure(self) -> None:
        snapshot = Snapshot(
            assets=[
                Asset(
                    "server:vpn-only",
                    "server",
                    "vpn-only",
                    {
                        "public_ip": "192.0.2.100",
                        "firewall_attached": True,
                        "inbound": [{"protocol": "tcp", "port": 22, "sources": ["100.64.0.0/10"]}],
                    },
                )
            ]
        )
        self.assertEqual(hunt(snapshot), [])

    def test_unattached_broad_rule_is_rejected(self) -> None:
        snapshot = Snapshot(
            assets=[
                Asset(
                    "server:detached",
                    "server",
                    "detached",
                    {
                        "firewall_attached": False,
                        "inbound": [{"protocol": "tcp", "port": 22, "sources": ["0.0.0.0/0"]}],
                    },
                )
            ]
        )
        from hetzner_security.verification import verify_all

        findings = verify_all(hunt(snapshot), snapshot)
        self.assertEqual(findings[0].status.value, "rejected")
        self.assertIsNone(findings[0].severity)

    def test_provider_rule_without_downstream_evidence_needs_validation(self) -> None:
        snapshot = Snapshot(
            assets=[
                Asset(
                    "server:ssh",
                    "server",
                    "ssh",
                    {
                        "firewall_attached": True,
                        "inbound": [{"protocol": "tcp", "port": 22, "sources": ["0.0.0.0/0"]}],
                    },
                )
            ]
        )
        from hetzner_security.verification import verify_all

        finding = verify_all(hunt(snapshot), snapshot)[0]
        self.assertEqual(finding.status.value, "needs_validation")
        self.assertIsNone(finding.severity)

    def test_scanner_signal_without_runtime_applicability_needs_validation(self) -> None:
        snapshot = Snapshot(
            assets=[Asset("container:api", "container", "api")],
            signals=[
                {
                    "type": "vulnerability",
                    "scanner": "trivy",
                    "asset_id": "container:api",
                    "vulnerability_id": "CVE-DEMO",
                    "package": "demo",
                    "installed_version": "1",
                    "fixed_version": "2",
                    "severity": "HIGH",
                }
            ],
        )
        from hetzner_security.verification import verify_all

        finding = verify_all(hunt(snapshot), snapshot)[0]
        self.assertEqual(finding.status.value, "needs_validation")
        self.assertIsNone(finding.severity)

    def test_unreachable_postgres_trust_rule_needs_validation(self) -> None:
        postgres = Asset(
            "postgres:isolated",
            "postgres",
            "isolated",
            {
                "service": "postgres",
                "port": 5432,
                "pg_hba": [{"address": "0.0.0.0/0", "method": "trust"}],
            },
        )
        snapshot = Snapshot(assets=[postgres])
        from hetzner_security.verification import verify_all

        finding = verify_all(hunt(snapshot), snapshot)[0]
        self.assertEqual(finding.status.value, "needs_validation")
        self.assertIsNone(finding.severity)

    def test_redis_path_is_confirmed_when_graph_reaches_listener(self) -> None:
        source = Asset("container:client", "container", "client")
        redis = Asset(
            "redis:prod",
            "redis",
            "redis",
            {
                "service": "redis",
                "port": 6379,
                "bind": ["0.0.0.0"],
                "protected_mode": False,
                "acl_enabled": False,
            },
        )
        edge = Edge(
            "container:client",
            "redis:prod",
            "allows",
            "tcp",
            6379,
            (Evidence("fixture", "path", "redis:prod", True),),
        )
        snapshot = Snapshot(assets=[source, redis], edges=[edge])
        from hetzner_security.verification import verify_all

        finding = verify_all(hunt(snapshot), snapshot)[0]
        self.assertEqual(finding.status.value, "confirmed")


if __name__ == "__main__":
    unittest.main()
