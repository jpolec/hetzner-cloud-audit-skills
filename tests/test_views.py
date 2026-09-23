from __future__ import annotations

import json
import tempfile
import unittest
import xml.dom.minidom
from pathlib import Path

from hetzner_security.cli.main import build_parser, run
from hetzner_security.models import Asset, Snapshot

FIXTURES = Path(__file__).parent / "fixtures"


class ViewsTest(unittest.TestCase):
    """Every map view renders valid SVG with and without the optional evidence sources."""

    def test_all_views_render(self) -> None:
        server = Asset("hcloud:server:1", "server", "app-1", {
            "public_ip": True, "firewall_attached": True, "private_net": [],
            "inbound": [{"direction": "in", "protocol": "tcp", "port_from": 9001, "port_to": 9001, "sources": ["0.0.0.0/0"]}],
        }, {"environment": "production", "role": "app"}, "hcloud_api")
        with tempfile.TemporaryDirectory() as tmp:
            snap = Path(tmp) / "snap.json"
            snap.write_text(json.dumps(Snapshot(assets=[server], metadata={"collected_at": "2026-09-23T00:00:00+00:00"}).to_dict()))
            extra = ["--host-bundle", str(FIXTURES / "host" / "app-1.bundle"), "--robot", str(FIXTURES / "robot" / "robot.json"),
                     "--k8s", str(FIXTURES / "k8s" / "cluster.json")]
            for view in ("architecture", "connectivity", "cost", "host", "posture"):
                for flags in ([], extra):
                    out = Path(tmp) / f"{view}.svg"
                    args = build_parser().parse_args(["map", "--input", str(snap), "--format", "svg", "--view", view, "--output", str(out), *flags])
                    self.assertEqual(run(args), 0)
                    xml.dom.minidom.parseString(out.read_text())  # noqa: S318 -- our own output; checks it is well-formed
            self.assertIn("docker bypass", (Path(tmp) / "architecture.svg").read_text())
            self.assertIn("DEDICATED SERVERS", (Path(tmp) / "architecture.svg").read_text())


if __name__ == "__main__":
    unittest.main()
