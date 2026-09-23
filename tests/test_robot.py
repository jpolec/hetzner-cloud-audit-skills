from __future__ import annotations

import io
import json
import unittest
import urllib.error
from pathlib import Path
from typing import Any

from hetzner_security.analyzers import hunt
from hetzner_security.collectors.robot import (
    ReadOnlyRobotCollector,
    apply_robot,
    load_robot_file,
    robot_world_ports,
)
from hetzner_security.flows import PortSet
from hetzner_security.graph import AttackGraph
from hetzner_security.models import Asset, Snapshot
from hetzner_security.verification import verify_all

FIXTURE = Path(__file__).parent / "fixtures" / "robot" / "robot.json"


def _snapshot() -> Snapshot:
    network = Asset("hcloud:network:4711", "network", "shop-net", {"ip_range": "10.0.0.0/16"}, {}, "hcloud_api")
    snapshot = Snapshot(assets=[network], metadata={"collected_at": "2026-09-23T00:00:00+00:00"})
    return apply_robot(snapshot, load_robot_file(FIXTURE))


class RobotTest(unittest.TestCase):
    def test_first_match_discard_shadows_later_accept(self) -> None:
        rules = load_robot_file(FIXTURE)["firewall"]["321"]["firewall"]["rules"]["input"]
        world = robot_world_ports(rules)
        self.assertIn(22, world)
        self.assertNotIn(5432, world)  # the office accept is source-specific, the discard comes before the late accept
        self.assertFalse(world.intersection(PortSet.of([(40000, 40000)])))  # the ephemeral rule is ACK-only

    def test_findings(self) -> None:
        snapshot = _snapshot()
        findings = verify_all(hunt(snapshot), snapshot)
        by_rule: dict[str, list[str]] = {}
        for item in findings:
            by_rule.setdefault(item.rule_id, []).extend(item.assets)
        self.assertEqual(by_rule["HETZ-ROB-001"], ["robot:server:322"])  # firewall disabled
        self.assertIn("robot:server:321", by_rule["HETZ-ROB-002"])  # SSH from anywhere
        self.assertNotIn("robot:server:323", by_rule["HETZ-ROB-002"])  # only 443 public, SSH via VPN range
        self.assertEqual(by_rule["HETZ-ROB-005"], ["robot:server:321"])  # IPv6 not filtered
        self.assertIn("hcloud:network:4711", by_rule["HETZ-ROB-003"])
        self.assertIn("robot:ssh_key:56:29:99:a4:5d:ed:ac:95:c1:f5:88:82:90:5d:dd:10", by_rule["HETZ-KEY-001"])
        statuses = {item.rule_id: item.status.value for item in findings}
        self.assertEqual(statuses["HETZ-ROB-001"], "needs_validation")
        self.assertEqual(statuses["HETZ-ROB-003"], "confirmed")

    def test_vswitch_links_dedicated_and_cloud(self) -> None:
        graph = AttackGraph(_snapshot())
        self.assertTrue(graph.reachable("hcloud:network:4711", "robot:server:321"))
        self.assertTrue(graph.reachable("internet", "robot:server:322", protocol="tcp", port=5432))
        self.assertFalse(graph.reachable("internet", "robot:server:323", protocol="tcp", port=22))

    def test_live_client_is_get_only_and_tolerates_404(self) -> None:
        raw = load_robot_file(FIXTURE)
        routes: dict[str, Any] = {
            "server": raw["server"], "firewall/321": raw["firewall"]["321"], "firewall/322": raw["firewall"]["322"],
            "firewall/323": raw["firewall"]["323"], "vswitch": [{"id": 4321}], "vswitch/4321": raw["vswitch"][0], "key": raw["key"],
        }

        class Response(io.BytesIO):
            def __enter__(self) -> Response:
                return self

            def __exit__(self, *args: object) -> None:
                return None

        def fake(request: Any, timeout: int = 0) -> Response:
            self.assertEqual(request.get_method(), "GET")
            self.assertTrue(request.headers["Authorization"].startswith("Basic "))
            path = request.full_url.removeprefix("https://robot-ws.your-server.de/")
            if path not in routes:
                raise urllib.error.HTTPError(request.full_url, 404, "not found", None, None)  # type: ignore[arg-type]
            return Response(json.dumps(routes[path]).encode())

        collector = ReadOnlyRobotCollector("user", "pass")  # noqa: S106
        collector._urlopen = fake
        fetched = collector.fetch()
        self.assertEqual(len(fetched["server"]), 3)
        self.assertEqual(len(fetched["vswitch"]), 1)


if __name__ == "__main__":
    unittest.main()
