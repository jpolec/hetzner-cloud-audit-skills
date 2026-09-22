from __future__ import annotations

import unittest

from hetzner_security.analyzers import hunt
from hetzner_security.models import Asset, Snapshot


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


if __name__ == "__main__":
    unittest.main()
