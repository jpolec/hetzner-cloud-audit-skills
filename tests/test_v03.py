from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from hetzner_security.analyzers import hunt
from hetzner_security.cli.main import _answer, build_parser, run
from hetzner_security.collectors.fixture import load_snapshot
from hetzner_security.collectors.hcloud import ReadOnlyHCloudCollector
from hetzner_security.cost import analyze_cost
from hetzner_security.graph import AttackGraph
from hetzner_security.models import Asset, Edge, Evidence, Fact, Snapshot
from hetzner_security.policy import apply_policy
from hetzner_security.temporal import diff_snapshots
from hetzner_security.verification import verify_all

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - optional dev dependency
    Draft202012Validator = None  # type: ignore[assignment,misc]


class V03Test(unittest.TestCase):
    def test_live_shape_is_normalized_into_cloud_path_and_temporal_facts(self) -> None:
        class FixtureCollector(ReadOnlyHCloudCollector):
            def _get_page(self, endpoint: str, page: int):  # type: ignore[no-untyped-def]
                rows = {
                    "servers": [
                        {
                            "id": 1,
                            "name": "synthetic-worker",
                            "status": "running",
                            "labels": {"environment": "staging", "project": "worker"},
                            "public_net": {"ipv4": {"ip": "192.0.2.10"}, "ipv6": {}, "firewalls": [{"id": 10}]},
                            "private_net": [{"network": 20, "ip": "10.0.1.2"}],
                            "volumes": [],
                            "protection": {"delete": False},
                            "server_type": {"name": "demo", "cores": 2, "memory": 4, "prices": []},
                            "location": {"name": "fsn1"},
                        },
                        {
                            "id": 2,
                            "name": "synthetic-db",
                            "status": "running",
                            "labels": {"environment": "production", "project": "database", "role": "db"},
                            "public_net": {"ipv4": {"ip": "192.0.2.11"}, "ipv6": {}, "firewalls": [{"id": 11}]},
                            "private_net": [{"network": 20, "ip": "10.0.1.3"}],
                            "volumes": [30],
                            "protection": {"delete": False},
                            "server_type": {"name": "demo", "cores": 2, "memory": 4, "prices": []},
                            "location": {"name": "fsn1"},
                        },
                    ],
                    "networks": [{"id": 20, "name": "synthetic-shared", "ip_range": "10.0.0.0/16", "labels": {}, "protection": {"delete": False}}],
                    "firewalls": [
                        {"id": 10, "name": "worker", "labels": {}, "applied_to": [{"type": "server", "server": {"id": 1}}], "rules": []},
                        {"id": 11, "name": "db", "labels": {}, "applied_to": [{"type": "server", "server": {"id": 2}}], "rules": [{"direction": "in", "protocol": "tcp", "port": "any", "source_ips": ["10.0.0.0/16"], "destination_ips": []}]},
                    ],
                }
                key = endpoint.removeprefix("hetzner:")
                return {key: rows.get(endpoint, rows.get(key, [])), "meta": {"pagination": {"next_page": None}}}

        snapshot = FixtureCollector(token="fixture-not-a-real-token").collect()  # noqa: S106
        server = snapshot.asset_map()["hcloud:server:2"]
        self.assertTrue(server.properties["firewall_attached"])
        self.assertEqual(server.properties["inbound"][0]["sources"], ["10.0.0.0/16"])
        self.assertTrue(snapshot.facts)
        result = AttackGraph(snapshot).explain_path("synthetic-worker", "synthetic-db", protocol="tcp", port=5432)
        self.assertEqual(result["result"], "cloud_path_present")
        finding = next(item for item in verify_all(hunt(snapshot), snapshot) if item.rule_id == "HETZ-XLY-002")
        self.assertEqual(finding.status.value, "needs_validation")
        self.assertIsNone(finding.severity)

    def test_snapshot_diff_reports_new_exposure_and_coverage_regression(self) -> None:
        fact_before = Fact("fact-a", "status", "server:a", "off", "fixture", "2026-09-20T00:00:00+00:00", "0.3.0", "run-before")
        fact_after = Fact("fact-a", "status", "server:a", "running", "fixture", "2026-09-22T00:00:00+00:00", "0.3.0", "run-after")
        before = Snapshot(
            assets=[
                Asset("server:a", "server", "a"),
                Asset("firewall:old", "firewall", "old-firewall"),
            ],
            edges=[Edge("firewall:old", "server:a", "protects")],
            facts=[fact_before],
            metadata={"run_id": "run-before", "coverage": {"firewall": {"status": "collected"}}},
        )
        after = Snapshot(
            assets=[Asset("server:a", "server", "a")],
            edges=[Edge("internet", "server:a", "allows", "tcp", 443)],
            facts=[fact_after],
            metadata={"run_id": "run-after", "coverage": {"firewall": {"status": "failed"}}},
        )
        diff = diff_snapshots(before, after)
        self.assertTrue(diff["security_regression"])
        self.assertEqual(len(diff["new_exposures"]), 1)
        self.assertEqual(len(diff["changed_facts"]), 1)
        self.assertEqual(len(diff["coverage_regressions"]), 1)
        self.assertEqual(diff["removed_assets"], [])
        self.assertEqual(diff["uncertain_removed_assets"], ["firewall:old"])
        self.assertEqual(diff["removed_edges"], [])
        self.assertEqual(len(diff["uncertain_removed_edges"]), 1)

    def test_cost_report_quantifies_non_overlapping_potential_savings(self) -> None:
        current_type = {
            "name": "synthetic-large",
            "architecture": "x86",
            "cpu_type": "shared",
            "cores": 4,
            "memory": 8,
            "prices": [{"location": "fsn1", "price_monthly": {"net": "100"}}],
        }
        metrics = {"time_series": {"cpu": {"values": [[1, "20"], [2, "40"]]}}}
        running = Asset(
            "hcloud:server:1",
            "server",
            "synthetic-running",
            {"id": 1, "status": "running", "location": {"name": "fsn1"}, "server_type": current_type, "metrics": metrics, "backup_enabled": False},
            {"environment": "production"},
            "hcloud_api",
        )
        stopped = Asset(
            "hcloud:server:2",
            "server",
            "synthetic-stopped",
            {"id": 2, "status": "off", "location": {"name": "fsn1"}, "server_type": {**current_type, "prices": [{"location": "fsn1", "price_monthly": {"net": "20"}}]}, "metrics": {}, "backup_enabled": False},
            {},
            "hcloud_api",
        )
        candidate = Asset(
            "hcloud:server_type:2",
            "server_type",
            "synthetic-medium",
            {"name": "synthetic-medium", "architecture": "x86", "cpu_type": "shared", "cores": 2, "memory": 4, "deprecated": False, "locations": [{"name": "fsn1", "available": True}], "prices": [{"location": "fsn1", "price_monthly": {"net": "60"}}]},
            source="hcloud_api",
        )
        pricing = Asset("hcloud:pricing:current", "pricing", "pricing", {"currency": "EUR", "server_backup": {"percentage": "20"}, "volume": {"price_per_gb_month": {"net": "0"}}, "primary_ips": []}, source="hcloud_api")
        report = analyze_cost(Snapshot(assets=[running, stopped, candidate, pricing], metadata={"collected_at": "2026-09-22T00:00:00+00:00"}))
        self.assertEqual(report["current_catalog_estimate"]["monthly_net"], 120.0)
        self.assertEqual(report["identified_potential_savings"]["monthly_net"], 60.0)
        self.assertEqual(report["identified_potential_savings"]["annual_net"], 720.0)
        self.assertEqual(report["identified_potential_savings"]["confirmed_monthly_net"], 0.0)
        if Draft202012Validator is not None:
            schema = json.loads((Path(__file__).parents[1] / "schemas" / "architecture-recommendation.schema.json").read_text())
            validator = Draft202012Validator(schema)
            for recommendation in report["recommendations"]:
                validator.validate(recommendation)

    def test_snapshot_cli_round_trip(self) -> None:
        source = Snapshot(
            assets=[Asset("server:a", "server", "synthetic")],
            edges=[Edge("internet", "server:a", "public_interface", evidence=(Evidence("fixture", "public", "server:a", True),))],
            facts=[Fact("fact-a", "status", "server:a", "running", "fixture", "2026-09-22T00:00:00+00:00", "0.3.0", "run-a")],
            metadata={"run_id": "run-a"},
        )
        with tempfile.TemporaryDirectory() as temp:
            input_path = Path(temp) / "input.json"
            output_path = Path(temp) / "output.json"
            input_path.write_text(json.dumps(source.to_dict()))
            args = build_parser().parse_args(["snapshot", "--input", str(input_path), "--output", str(output_path), "--format", "json"])
            self.assertEqual(run(args), 0)
            loaded = load_snapshot(output_path)
            self.assertEqual(loaded.facts[0].run_id, "run-a")

    def test_cost_report_includes_unattached_volume_waste(self) -> None:
        volume = Asset(
            "hcloud:volume:9",
            "volume",
            "synthetic-unattached",
            {"id": 9, "server": None, "size": 100},
            source="hcloud_api",
        )
        pricing = Asset(
            "hcloud:pricing:current",
            "pricing",
            "pricing",
            {
                "currency": "EUR",
                "server_backup": {"percentage": "20"},
                "volume": {"price_per_gb_month": {"net": "0.05"}},
                "primary_ips": [],
            },
            source="hcloud_api",
        )
        report = analyze_cost(
            Snapshot(
                assets=[volume, pricing],
                metadata={"collected_at": "2026-09-22T00:00:00+00:00"},
            )
        )
        self.assertEqual(report["current_catalog_estimate"]["monthly_net"], 5.0)
        self.assertEqual(report["identified_potential_savings"]["monthly_net"], 5.0)
        self.assertEqual(report["recommendations"][0]["rule_id"], "HETZ-COST-004")

    def test_owner_policy_drives_cross_environment_finding(self) -> None:
        source = Asset(
            "server:stage",
            "server",
            "synthetic-stage",
            labels={"environment": "staging"},
        )
        target = Asset(
            "postgres:prod",
            "postgres",
            "synthetic-prod-db",
            {"service": "postgres", "port": 5432, "host_firewall_allows_source": True},
            {"environment": "production"},
        )
        edge = Edge("server:stage", "postgres:prod", "allows", "tcp", 5432)
        snapshot = apply_policy(
            Snapshot(assets=[source, target], edges=[edge]),
            {"environments": {"production": {"may_receive_from": ["production"]}}},
            source="policy.toml",
        )
        findings = hunt(snapshot)
        self.assertTrue(any(item.rule_id == "HETZ-XLY-001" for item in findings))

    def test_ask_finds_container_to_production_database_path(self) -> None:
        snapshot = load_snapshot(
            Path(__file__).parents[1] / "benchmarks" / "scenarios" / "v0.1-insecure.json"
        )
        answer = _answer(snapshot, "Can anything in staging reach production databases?")
        self.assertEqual(answer["result"], "reachable")
        self.assertTrue(answer["paths"])
        self.assertEqual(answer["paths"][0]["port"], 5432)

    def test_ask_separates_direct_internet_exposure_from_pivots(self) -> None:
        web = Asset("server:web", "server", "web")
        db = Asset("server:db", "server", "synthetic-db", labels={"role": "db"})
        snapshot = Snapshot(
            assets=[web, db, Asset("net", "network", "net")],
            edges=[
                Edge("internet", "server:web", "allows", "tcp", 443),
                Edge("server:web", "net", "attached_to"),
                Edge("net", "server:db", "allows", "tcp", None),
            ],
        )
        answer = _answer(snapshot, "Can the Internet reach any database?")
        self.assertEqual(answer["result"], "no_confirmed_path")
        self.assertEqual(len(answer["indirect_paths"]), 1)
        self.assertIn("indirect", answer["answer"])

    def test_cloudflare_origin_bypass_needs_validation(self) -> None:
        def web(name: str, sources: list[str]) -> Asset:
            inbound = [
                {"protocol": "tcp", "port_from": 443, "port_to": 443, "sources": sources},
                {"protocol": "tcp", "port_from": None, "port_to": None, "sources": ["10.0.0.0/16", "100.64.0.0/10"]},
            ]
            return Asset(f"hcloud:server:{name}", "server", name, {"public_ip": True, "firewall_attached": True, "inbound": inbound}, source="hcloud_api")

        snapshot = Snapshot(assets=[web("fronted", ["173.245.48.0/20"]), web("direct", ["0.0.0.0/0"])])
        findings = [item for item in verify_all(hunt(snapshot), snapshot) if item.rule_id == "HETZ-NET-006"]
        self.assertEqual([item.assets for item in findings], [["hcloud:server:direct"]])
        self.assertEqual(findings[0].status.value, "needs_validation")
        alone = Snapshot(assets=[web("direct", ["0.0.0.0/0"])])
        self.assertFalse([item for item in hunt(alone) if item.rule_id == "HETZ-NET-006"])

    def test_markdown_groups_single_asset_findings(self) -> None:
        from hetzner_security.findings import render_markdown

        servers = [
            Asset(f"hcloud:server:{index}", "server", f"db-{index}", {"stateful": True, "backup_enabled": False}, {"environment": "production"}, "hcloud_api")
            for index in range(3)
        ]
        snapshot = Snapshot(assets=servers)
        findings = [item for item in verify_all(hunt(snapshot), snapshot) if item.rule_id == "HETZ-BCP-001"]
        self.assertEqual(len(findings), 3)
        report = render_markdown(findings, names={item.id: item.name for item in servers})
        self.assertEqual(report.count("HETZ-BCP-001"), 1)
        self.assertIn("(3 assets)", report)
        self.assertIn("db-0, db-1, db-2", report)

    def test_audit_markdown_starts_with_at_a_glance(self) -> None:
        from hetzner_security.findings import render_markdown
        from hetzner_security.findings.summary import build_summary

        server = Asset("hcloud:server:1", "server", "db-0", {"stateful": True, "backup_enabled": False, "location": {"name": "fsn1"}}, {"environment": "production"}, "hcloud_api")
        network = Asset("hcloud:network:1", "network", "net", {"ip_range": "10.0.0.0/16"}, source="hcloud_api")
        snapshot = Snapshot(assets=[server, network], metadata={"coverage": {"server": {"status": "collected"}, "volume": {"status": "failed"}}})
        findings = verify_all(hunt(snapshot), snapshot)
        report = render_markdown(findings, snapshot.metadata, summary=build_summary(snapshot, findings))
        self.assertTrue(report.split("\n")[2].startswith("## At a glance"))
        self.assertIn("1 server · 1 network · 1 location (fsn1)", report)
        self.assertIn("Endpoint volume (failed)", report)
        self.assertIn("Host firewall: not collected", report)
        self.assertNotIn("## Summary", report)

    def test_deprecated_server_type_is_reported(self) -> None:
        server = Asset(
            "hcloud:server:1",
            "server",
            "legacy",
            {"server_type": {"name": "cx22", "deprecated": True, "deprecation": {"unavailable_after": "2025-12-31T23:59:59Z"}}},
            source="hcloud_api",
        )
        snapshot = Snapshot(assets=[server])
        findings = verify_all(hunt(snapshot), snapshot)
        finding = next(item for item in findings if item.rule_id == "HETZ-GOV-003")
        self.assertEqual(finding.status.value, "confirmed")
        self.assertIn("cx22", finding.observation)


if __name__ == "__main__":
    unittest.main()
