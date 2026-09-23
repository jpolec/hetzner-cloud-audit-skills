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

    def test_get_retries_429_and_5xx_then_succeeds(self) -> None:
        import email.message
        import io
        import urllib.error

        calls: list[int] = []
        sleeps: list[float] = []

        class Response(io.BytesIO):
            def __enter__(self):  # type: ignore[no-untyped-def]
                return self

            def __exit__(self, *args):  # type: ignore[no-untyped-def]
                return False

        def fake_urlopen(request, timeout):  # type: ignore[no-untyped-def]
            calls.append(1)
            if len(calls) == 1:
                headers = email.message.Message()
                headers["Retry-After"] = "2"
                raise urllib.error.HTTPError(request.full_url, 429, "Too Many Requests", headers, None)
            if len(calls) == 2:
                raise urllib.error.HTTPError(request.full_url, 503, "Unavailable", email.message.Message(), None)
            return Response(b'{"servers": []}')

        collector = ReadOnlyHCloudCollector(token="fixture")  # noqa: S106
        collector._urlopen = fake_urlopen
        collector._sleep = sleeps.append
        self.assertEqual(collector._get_json("servers"), {"servers": []})
        self.assertEqual(len(calls), 3)
        self.assertEqual(sleeps[0], 2.0)  # Retry-After honored

    def test_get_does_not_retry_auth_errors(self) -> None:
        import email.message
        import urllib.error

        from hetzner_security.collectors.hcloud import HCloudCollectionError

        calls: list[int] = []

        def fake_urlopen(request, timeout):  # type: ignore[no-untyped-def]
            calls.append(1)
            raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", email.message.Message(), None)

        collector = ReadOnlyHCloudCollector(token="fixture")  # noqa: S106
        collector._urlopen = fake_urlopen
        collector._sleep = lambda _: None
        with self.assertRaises(HCloudCollectionError) as raised:
            collector._get_json("servers")
        self.assertEqual(raised.exception.status, 401)
        self.assertEqual(len(calls), 1)

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

    def test_stateful_detection_uses_volumes_roles_and_labels(self) -> None:
        from hetzner_security.collectors.hcloud import _is_stateful

        self.assertTrue(_is_stateful({"name": "pg-main", "labels": {}}))  # database on the root disk
        self.assertTrue(_is_stateful({"name": "x", "labels": {"role": "db"}}))
        self.assertTrue(_is_stateful({"name": "web-1", "labels": {}, "volumes": [1]}))
        self.assertFalse(_is_stateful({"name": "web-1", "labels": {}}))
        self.assertFalse(_is_stateful({"name": "db-cache", "labels": {"stateful": "false"}, "volumes": [1]}))

    def test_ssh_key_strength_is_recorded_before_redaction(self) -> None:
        import base64

        from hetzner_security.collectors.hcloud import _normalize_resources, _ssh_key_strength

        def field(data: bytes) -> bytes:
            return len(data).to_bytes(4, "big") + data

        modulus = (1 << 2047) | 1  # 2048-bit
        blob = field(b"ssh-rsa") + field((65537).to_bytes(3, "big")) + field(b"\x00" + modulus.to_bytes(256, "big"))
        key = "ssh-rsa " + base64.b64encode(blob).decode() + " someone@example.com"
        self.assertEqual(_ssh_key_strength(key), ("ssh-rsa", 2048))
        self.assertEqual(_ssh_key_strength("ssh-ed25519 AAAA x"), ("ssh-ed25519", 256))
        normalized = _sanitize_resource(_normalize_resources({"ssh_key": [{"id": 1, "public_key": key}]}))
        row = normalized["ssh_key"][0]
        self.assertEqual((row["key_type"], row["key_bits"]), ("ssh-rsa", 2048))
        self.assertNotIn("AAAA", row["public_key"])

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
