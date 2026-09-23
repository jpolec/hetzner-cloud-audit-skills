from __future__ import annotations

import unittest

from hetzner_security.collectors.hcloud import (
    ReadOnlyHCloudCollector,
    _derive_edges,
    _sanitize_resource,
)
from hetzner_security.graph import AttackGraph
from hetzner_security.models import Asset, Snapshot


class CollectorSafetyTest(unittest.TestCase):
    def test_sensitive_fields_are_redacted(self) -> None:
        value = _sanitize_resource({"name": "x", "token": "secret", "nested": {"user_data": "bad"}})
        self.assertEqual(value["token"], "[REDACTED]")
        self.assertEqual(value["nested"]["user_data"], "[REDACTED]")

    def test_private_network_is_unfiltered_by_cloud_firewalls(self) -> None:
        # Hetzner Cloud Firewalls do not filter private network traffic: a member with no
        # private-source rule is still reachable from the network on any port.
        raw = {
            "server": [
                {"id": 1, "public_net": {}, "private_net": [{"network": 9, "ip": "10.0.1.2"}], "inbound": []},
                {"id": 2, "public_net": {}, "private_net": [{"network": 9, "ip": "10.0.1.3"}], "inbound": []},
            ],
            "network": [{"id": 9, "ip_range": "10.0.0.0/16"}],
        }
        edges = [edge for edge in _derive_edges(raw) if edge.source == "hcloud:network:9" and edge.relation == "allows"]
        self.assertEqual({edge.target for edge in edges}, {"hcloud:server:1", "hcloud:server:2"})
        self.assertEqual(edges[0].evidence[0].kind, "private_network_unfiltered")
        snapshot = Snapshot(assets=[Asset("hcloud:server:1", "server", "a"), Asset("hcloud:server:2", "server", "b")], edges=_derive_edges(raw))
        self.assertTrue(AttackGraph(snapshot).reachable("hcloud:server:1", "hcloud:server:2", protocol="tcp", port=6379))

    def test_personal_data_is_redacted(self) -> None:
        value = _sanitize_resource(
            {
                "public_key": "ssh-ed25519 AAAAC3Nza owner@example.com",
                "fingerprint": "a4:95:53",
                "username": "u123456",
                "public_net": {"ipv4": {"ip": "192.0.2.10", "dns_ptr": "static.example.net"}, "ipv6": {"dns_ptr": []}},
                "labels": {"owner": "ops@example.com"},
                "server": "u123456.your-storagebox.de",
            }
        )
        self.assertEqual(value["server"], "[REDACTED:storage-box-host]")
        self.assertEqual(value["public_key"], "ssh-ed25519 [key material and comment omitted]")
        self.assertEqual(value["fingerprint"], "a4:95:53")
        self.assertEqual(value["username"], "[REDACTED:personal]")
        self.assertEqual(value["public_net"]["ipv4"]["dns_ptr"], "[REDACTED:personal]")
        self.assertEqual(value["public_net"]["ipv4"]["ip"], "192.0.2.10")
        self.assertEqual(value["public_net"]["ipv6"]["dns_ptr"], [])
        self.assertEqual(value["labels"]["owner"], "[REDACTED:email]")

    def test_collector_has_no_mutation_api(self) -> None:
        methods = set(dir(ReadOnlyHCloudCollector))
        self.assertTrue({"collect", "_get_page", "_list"} <= methods)
        self.assertFalse(methods & {"create", "update", "delete", "post", "put", "patch"})

    def test_snapshot_backup_and_dns_types_are_normalized(self) -> None:
        class FixtureCollector(ReadOnlyHCloudCollector):
            def _get_page(self, endpoint: str, page: int):  # type: ignore[no-untyped-def]
                rows = {
                    "images": [
                        {"id": 1, "description": "snap", "type": "snapshot"},
                        {"id": 2, "description": "backup", "type": "backup"},
                    ],
                    "zones": [{"id": 3, "name": "example.invalid"}],
                    "zones/3/rrsets": [{"name": "www", "type": "A", "records": []}],
                }
                key = "rrsets" if endpoint.endswith("/rrsets") else endpoint
                return {key: rows.get(endpoint, []), "meta": {"pagination": {"next_page": None}}}

        snapshot = FixtureCollector(token="fixture-not-a-real-token").collect()  # noqa: S106
        asset_types = {asset.type for asset in snapshot.assets}
        self.assertTrue({"snapshot", "backup", "zone", "dns_rrset"} <= asset_types)


if __name__ == "__main__":
    unittest.main()
