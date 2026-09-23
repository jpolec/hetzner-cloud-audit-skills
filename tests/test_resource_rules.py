from __future__ import annotations

import unittest

from hetzner_security.analyzers import hunt
from hetzner_security.models import Asset, Snapshot
from hetzner_security.verification import verify_all

NOW = {"collected_at": "2026-09-23T00:00:00+00:00"}


def _findings(*assets: Asset) -> dict[str, str]:
    snapshot = Snapshot(assets=list(assets), metadata=NOW)
    return {item.rule_id: item.status.value for item in verify_all(hunt(snapshot), snapshot)}


def _asset(kind: str, name: str, props: dict[str, object], labels: dict[str, str] | None = None) -> Asset:
    return Asset(f"hcloud:{kind}:{name}", kind, name, props, labels or {}, "hcloud_api")


class StorageBoxTest(unittest.TestCase):
    def test_external_access_and_missing_snapshot_plan(self) -> None:
        risky = _asset("storage_box", "bk", {"access_settings": {"ssh_enabled": True, "reachable_externally": True}, "snapshot_plan": None})
        self.assertEqual(_findings(risky), {"HETZ-STO-001": "confirmed", "HETZ-STO-002": "confirmed"})

    def test_clean_twin(self) -> None:
        clean = _asset("storage_box", "bk", {"access_settings": {"ssh_enabled": True, "reachable_externally": False}, "snapshot_plan": {"max_snapshots": 7}})
        self.assertEqual(_findings(clean), {})


class ImageLifecycleTest(unittest.TestCase):
    def test_end_of_support_needs_validation_and_supported_is_clean(self) -> None:
        old = _asset("server", "old", {"image": {"os_flavor": "ubuntu", "os_version": "20.04", "name": "ubuntu-20.04"}})
        new = _asset("server", "new", {"image": {"os_flavor": "ubuntu", "os_version": "24.04", "name": "ubuntu-24.04"}})
        self.assertEqual(_findings(old).get("HETZ-IMG-001"), "needs_validation")
        self.assertNotIn("HETZ-IMG-001", _findings(new))


class LoadBalancerTest(unittest.TestCase):
    def _lb(self, services: list[dict[str, object]], targets: list[dict[str, object]]) -> Asset:
        return _asset("load_balancer", "lb", {"public_net": {"enabled": True}, "services": services, "targets": targets})

    def test_empty_plain_http_unhealthy_and_single_target(self) -> None:
        self.assertIn("HETZ-LB-001", _findings(self._lb([], [])))
        http_only = self._lb(
            [{"protocol": "http", "listen_port": 80}],
            [{"type": "server", "server": {"id": 1}, "health_status": [{"listen_port": 80, "status": "unhealthy"}]}],
        )
        found = _findings(http_only)
        self.assertTrue({"HETZ-LB-002", "HETZ-LB-004", "HETZ-LB-005"} <= set(found))
        no_redirect = self._lb(
            [{"protocol": "http", "listen_port": 80}, {"protocol": "https", "listen_port": 443, "http": {"redirect_http": False}}],
            [{"type": "server", "server": {"id": 1}}, {"type": "server", "server": {"id": 2}}],
        )
        self.assertIn("HETZ-LB-003", _findings(no_redirect))

    def test_clean_twin(self) -> None:
        clean = self._lb(
            [{"protocol": "https", "listen_port": 443, "http": {"redirect_http": True}}],
            [
                {"type": "server", "server": {"id": 1}, "health_status": [{"listen_port": 443, "status": "healthy"}]},
                {"type": "server", "server": {"id": 2}, "health_status": [{"listen_port": 443, "status": "healthy"}]},
            ],
        )
        self.assertFalse([rule for rule in _findings(clean) if rule.startswith("HETZ-LB-")])


class CertificateTest(unittest.TestCase):
    def test_expiring_failed_unused_and_clean(self) -> None:
        soon = _asset("certificate", "soon", {"not_valid_after": "2026-10-01T00:00:00Z", "used_by": [{"id": 1}], "status": {}})
        failed = _asset("certificate", "fail", {"not_valid_after": "2027-06-01T00:00:00Z", "used_by": [{"id": 1}], "status": {"renewal": "failed"}})
        unused = _asset("certificate", "unused", {"not_valid_after": "2027-06-01T00:00:00Z", "used_by": [], "status": {}})
        clean = _asset("certificate", "ok", {"not_valid_after": "2027-06-01T00:00:00Z", "used_by": [{"id": 1}], "status": {"renewal": "scheduled"}})
        self.assertIn("HETZ-CERT-001", _findings(soon))
        self.assertIn("HETZ-CERT-001", _findings(failed))
        self.assertIn("HETZ-CERT-002", _findings(unused))
        self.assertFalse([rule for rule in _findings(clean) if rule.startswith("HETZ-CERT-")])


class DnsTest(unittest.TestCase):
    def test_dangling_private_and_owned(self) -> None:
        server = _asset("server", "web", {"public_net": {"ipv4": {"ip": "203.0.113.10"}, "ipv6": {"ip": "2001:db8:1::/64"}}})

        def rrset(value: str, kind: str = "A") -> Asset:
            return _asset("dns_rrset", f"www-{value}", {"type": kind, "records": [{"value": value}]})

        self.assertEqual(_findings(server, rrset("198.51.100.7")).get("HETZ-DNS-001"), "needs_validation")
        self.assertIn("HETZ-DNS-002", _findings(server, rrset("10.0.0.5")))
        owned = _findings(server, rrset("203.0.113.10"), rrset("2001:db8:1::1", "AAAA"))
        self.assertFalse([rule for rule in owned if rule.startswith("HETZ-DNS-")])


class PlacementTest(unittest.TestCase):
    def test_redundant_role_without_spread_and_clean_twin(self) -> None:
        labels = {"environment": "production", "role": "db", "project": "shop"}
        a = _asset("server", "db-1", {}, labels)
        b = _asset("server", "db-2", {}, labels)
        self.assertIn("HETZ-PLC-001", _findings(a, b))
        spread = {"placement_group": {"type": "spread"}}
        self.assertNotIn("HETZ-PLC-001", _findings(_asset("server", "db-1", spread, labels), _asset("server", "db-2", spread, labels)))


if __name__ == "__main__":
    unittest.main()
