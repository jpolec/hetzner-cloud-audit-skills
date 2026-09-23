from __future__ import annotations

import io
import json
import unittest
from typing import Any

from hetzner_security.cost import analyze_cost
from hetzner_security.models import Asset, Snapshot
from hetzner_security.node_metrics import apply_node_metrics, collect_prometheus
from hetzner_security.temporal import diff_snapshots


def _type(name: str, cores: int, memory: float, disk: int, price: float) -> dict[str, Any]:
    return {"name": name, "cores": cores, "memory": memory, "disk": disk, "architecture": "x86", "cpu_type": "shared",
            "category": "cost_optimized", "deprecated": False,
            "prices": [{"location": "fsn1", "price_monthly": {"net": str(price)}}],
            "locations": [{"name": "fsn1", "available": True}]}


BIG = _type("cx42", 8, 16, 160, 18.0)
SMALL = _type("cx32", 4, 8, 80, 9.0)
TINY = _type("cx22", 2, 4, 40, 4.5)


def _snapshot(guest: dict[str, Any] | None, *, window_days: int = 30) -> Snapshot:
    # 30 days of CPU at 5% of one core on an 8-core server: clearly oversized on CPU alone.
    cpu = [[1_700_000_000 + i * 3600, "5.0"] for i in range(24 * window_days)]
    server = Asset("hcloud:server:1", "server", "app-1", {
        "id": 1, "status": "running", "server_type": BIG, "location": {"name": "fsn1"},
        "metrics": {"start": "2026-08-24T00:00:00+00:00", "end": "2026-09-23T00:00:00+00:00", "time_series": {"cpu": {"values": cpu}}},
    }, {}, "hcloud_api")
    types = [Asset(f"hcloud:server_type:{item['name']}", "server_type", str(item["name"]), item, {}, "hcloud_api") for item in (BIG, SMALL, TINY)]
    pricing = Asset("hcloud:pricing:current", "pricing", "pricing", {"currency": "EUR"}, {}, "hcloud_api")
    snapshot = Snapshot(assets=[server, *types, pricing],
                        metadata={"collected_at": "2026-09-23T00:00:00+00:00",
                                  "coverage": {"server_metrics": {"status": "collected", "window_days": window_days}}})
    if guest is not None:
        snapshot = apply_node_metrics(snapshot, {"window_days": 30, "source": "test", "hosts": {"app-1": guest}})
    return snapshot


class GuestTelemetryTest(unittest.TestCase):
    def test_without_guest_metrics_savings_are_theoretical_only(self) -> None:
        report = analyze_cost(_snapshot(None))
        savings = report["identified_potential_savings"]
        self.assertGreater(savings["theoretical_monthly_net"], 0)
        self.assertEqual(savings["expected_monthly_net"], 0)
        self.assertEqual(savings["verified_monthly_net"], 0)

    def test_ram_floor_blocks_too_small_candidates(self) -> None:
        # 60% of 16 GB at p95 needs >= 13.7 GB: cx32 (8 GB) must not be proposed.
        report = analyze_cost(_snapshot({"ram_p95_percent": 60, "ram_max_percent": 70, "disk_used_max_percent": 20,
                                         "disk_size_gb": 160, "coverage_days": 30}))
        self.assertFalse([rec for rec in report["recommendations"] if rec["rule_id"] == "HETZ-COST-002"])

    def test_complete_guest_evidence_makes_saving_expected(self) -> None:
        report = analyze_cost(_snapshot({"ram_p95_percent": 20, "ram_max_percent": 30, "ram_p95_7d_percent": 21,
                                         "disk_used_max_percent": 15, "disk_size_gb": 160, "coverage_days": 29}))
        rec = next(rec for rec in report["recommendations"] if rec["rule_id"] == "HETZ-COST-002")
        self.assertTrue(rec["evidence_complete"])
        self.assertEqual(rec["candidate_state"]["server_type"], "cx32")  # cx22 fails the 16 GB x 30% / 0.9 RAM floor
        self.assertGreater(report["identified_potential_savings"]["expected_monthly_net"], 0)

    def test_short_coverage_or_rising_ram_is_not_expected(self) -> None:
        for guest in ({"ram_p95_percent": 20, "disk_used_max_percent": 15, "coverage_days": 5},
                      {"ram_p95_percent": 20, "ram_p95_7d_percent": 35, "disk_used_max_percent": 15, "coverage_days": 30}):
            report = analyze_cost(_snapshot(guest))
            self.assertEqual(report["identified_potential_savings"]["expected_monthly_net"], 0, guest)

    def test_diff_reports_verified_saving(self) -> None:
        before = _snapshot(None)
        after = _snapshot(None)
        after.assets[0].properties["server_type"] = SMALL
        cost = diff_snapshots(before, after)["cost"]
        self.assertEqual(cost["verified_monthly_savings"], 9.0)

    def test_prometheus_collection_maps_nodename(self) -> None:
        responses = {
            "node_uname_info": [{"metric": {"instance": "10.0.0.2:9100", "nodename": "app-1"}, "value": [0, "1"]}],
        }

        def fake(request: Any, timeout: int = 0) -> Any:
            from urllib.parse import parse_qs, urlparse

            query = parse_qs(urlparse(request.full_url).query)["query"][0]
            self.assertEqual(request.get_method(), "GET")
            result = responses.get(query, [{"metric": {"instance": "10.0.0.2:9100"}, "value": [0, "42.5"]}])
            return io.BytesIO(json.dumps({"status": "success", "data": {"result": result}}).encode())

        data = collect_prometheus("http://prom:9090", 30, urlopen=_Ctx(fake))
        self.assertEqual(data["hosts"]["app-1"]["ram_p95_percent"], 42.5)


class _Ctx:
    """Wrap a fake urlopen so it works as a context manager."""

    def __init__(self, fn: Any) -> None:
        self.fn = fn

    def __call__(self, request: Any, timeout: int = 0) -> Any:
        body = self.fn(request, timeout)

        class Response:
            def __enter__(self) -> Any:
                return body

            def __exit__(self, *args: object) -> None:
                return None

        return Response()


if __name__ == "__main__":
    unittest.main()
