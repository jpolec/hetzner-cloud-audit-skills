"""End-to-end collector test on API-reference-shaped responses (load balancer, certificates, DNS).

The fixture follows the documented Hetzner Cloud response shapes with documentation IP ranges;
it is not captured from a real project. It exercises the path real responses take: pagination,
normalization, redaction, edge derivation, rules, and verification.
"""

from __future__ import annotations

import io
import json
import unittest
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Any

from hetzner_security.analyzers import hunt
from hetzner_security.collectors.hcloud import ReadOnlyHCloudCollector
from hetzner_security.graph import AttackGraph
from hetzner_security.verification import verify_all

RESPONSES: dict[str, Any] = json.loads((Path(__file__).parent / "fixtures" / "api" / "project.json").read_text())["responses"]


class _Response(io.BytesIO):
    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def _fake_urlopen(request: Any, timeout: int = 0) -> _Response:
    assert request.get_method() == "GET"  # noqa: S101 -- the collector must never write
    path = urllib.parse.urlparse(request.full_url).path.removeprefix("/v1/")
    if path not in RESPONSES:
        raise urllib.error.HTTPError(request.full_url, 404, "not found", None, None)  # type: ignore[arg-type]
    return _Response(json.dumps(RESPONSES[path]).encode())


def _collect() -> Any:
    collector = ReadOnlyHCloudCollector(token="fixture")  # noqa: S106
    collector._urlopen = _fake_urlopen
    collector._sleep = lambda _seconds: None
    return collector.collect()


class ApiShapedProjectTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.snapshot = _collect()
        cls.findings = verify_all(hunt(cls.snapshot), cls.snapshot)

    def _rules(self) -> dict[str, str]:
        return {item.rule_id: item.status.value for item in self.findings}

    def test_collector_normalizes_every_resource(self) -> None:
        types = {asset.type for asset in self.snapshot.assets}
        self.assertTrue({"server", "firewall", "network", "load_balancer", "certificate", "zone", "dns_rrset", "pricing"} <= types)
        self.assertEqual(self.snapshot.metadata["coverage"]["storage_box"]["status"], "unavailable")

    def test_secrets_and_personal_data_are_redacted(self) -> None:
        text = json.dumps(self.snapshot.to_dict())
        self.assertNotIn("BEGIN CERTIFICATE", text)
        self.assertNotIn("static.203.0.113.10.clients.example", text)

    def test_load_balancer_edges_resolve_label_selector_targets(self) -> None:
        graph = AttackGraph(self.snapshot)
        self.assertTrue(graph.reachable("internet", "hcloud:load_balancer:80", protocol="tcp", port=443))
        self.assertTrue(graph.reachable("hcloud:load_balancer:80", "hcloud:server:102", protocol="tcp", port=8080))

    def test_expected_rules_fire_on_realistic_shapes(self) -> None:
        rules = self._rules()
        self.assertEqual(rules.get("HETZ-LB-004"), "confirmed")  # web-b is unhealthy
        self.assertEqual(rules.get("HETZ-LB-006"), "needs_validation")  # backends open 8080 to the world
        self.assertIn("HETZ-CERT-001", rules)  # renewal failed, expires within 14 days
        self.assertIn("HETZ-CERT-002", rules)  # uploaded certificate used by nothing
        self.assertEqual(rules.get("HETZ-DNS-001"), "needs_validation")  # legacy A record points nowhere in the project
        dns = [item for item in self.findings if item.rule_id == "HETZ-DNS-001"]
        self.assertEqual(len(dns), 1)  # the record pointing at the load balancer is not dangling

    def test_clean_parts_stay_clean(self) -> None:
        rules = self._rules()
        self.assertNotIn("HETZ-LB-005", rules)  # two targets via label selector: not a single point of failure
        self.assertNotIn("HETZ-NET-005", rules)  # both servers have a firewall
