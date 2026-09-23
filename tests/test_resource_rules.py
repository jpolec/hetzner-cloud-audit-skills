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


class LoadBalancerGraphTest(unittest.TestCase):
    RAW = {
        "server": [
            {"id": 1, "name": "pg-main", "labels": {"role": "db"}, "public_net": {"ipv4": {"ip": "203.0.113.5"}}, "private_net": [], "inbound": [
                {"protocol": "tcp", "port_from": 5432, "port_to": 5432, "sources": ["0.0.0.0/0"]}
            ]},
        ],
        "load_balancer": [
            {"id": 9, "name": "lb", "public_net": {"enabled": True},
             "services": [{"protocol": "tcp", "listen_port": 5432, "destination_port": 5432}],
             "targets": [{"type": "label_selector", "targets": [{"type": "server", "server": {"id": 1}, "use_private_ip": True}]}]},
        ],
        "network": [],
    }

    def _snapshot(self) -> Snapshot:
        from hetzner_security.collectors.hcloud import _derive_edges

        server = _asset("server", "1", {**self.RAW["server"][0]}, {"role": "db"})
        server.name = "pg-main"
        lb = _asset("load_balancer", "9", self.RAW["load_balancer"][0])
        return Snapshot(assets=[server, lb], edges=_derive_edges(self.RAW), metadata=NOW)

    def test_lb_forwarding_is_direct_exposure_and_bypass_is_flagged(self) -> None:
        from hetzner_security.cli.main import _answer

        snapshot = self._snapshot()
        edges = {(edge.source, edge.target, edge.port) for edge in snapshot.edges if edge.relation == "allows"}
        self.assertIn(("internet", "hcloud:load_balancer:9", 5432), edges)
        self.assertIn(("hcloud:load_balancer:9", "hcloud:server:1", 5432), edges)
        answer = _answer(snapshot, "Can the Internet reach any database?")
        self.assertEqual(answer["indirect_paths"], [])  # through the LB is direct, not a pivot
        self.assertEqual(len(answer["paths"]), 1)
        self.assertEqual(_findings(*snapshot.assets).get("HETZ-LB-006"), None)  # edges needed: use hunt on snapshot
        findings = {item.rule_id: item.status.value for item in verify_all(hunt(snapshot), snapshot)}
        self.assertEqual(findings.get("HETZ-LB-006"), "needs_validation")


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


class SshKeyTest(unittest.TestCase):
    def test_weak_and_old_keys(self) -> None:
        weak = _asset("ssh_key", "old-rsa", {"key_type": "ssh-rsa", "key_bits": 2048, "created": "2021-01-01T00:00:00+00:00"})
        good = _asset("ssh_key", "ed", {"key_type": "ssh-ed25519", "key_bits": 256, "created": "2026-01-01T00:00:00+00:00"})
        self.assertEqual(set(_findings(weak)) & {"HETZ-KEY-001", "HETZ-KEY-002"}, {"HETZ-KEY-001", "HETZ-KEY-002"})
        self.assertFalse([rule for rule in _findings(good) if rule.startswith("HETZ-KEY-")])


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
