from __future__ import annotations

import unittest

from hetzner_security.diagram import render_svg
from hetzner_security.models import Asset, Snapshot
from hetzner_security.topology import (
    build_topology,
    classify_source,
    render_mermaid,
    render_topology_markdown,
)


def _server(name: str, role: str, inbound: list[dict[str, object]], networks: bool = True) -> Asset:
    return Asset(
        f"hcloud:server:{name}",
        "server",
        name,
        {
            "public_ip": True,
            "firewall_attached": True,
            "inbound": inbound,
            "private_net": [{"network": 1, "ip": "10.0.1.2"}] if networks else [],
            "public_net": {"ipv4": {"ip": "192.0.2.10"}},
            "server_type": {"name": "cx23"},
            "location": {"name": "fsn1"},
        },
        {"role": role},
        "hcloud_api",
    )


def _rule(protocol: str, port: int | None, sources: list[str]) -> dict[str, object]:
    return {"protocol": protocol, "port_from": port, "port_to": port, "sources": sources}


class TopologyTest(unittest.TestCase):
    def setUp(self) -> None:
        network = Asset("hcloud:network:1", "network", "synthetic-net", {"id": 1, "ip_range": "10.0.0.0/16"})
        self.snapshot = Snapshot(
            assets=[
                network,
                _server("synthetic-edge", "edge", [_rule("tcp", 443, ["173.245.48.0/20"]), _rule("icmp", None, ["0.0.0.0/0"])]),
                _server("synthetic-db", "db", [_rule("tcp", 5432, ["0.0.0.0/0"]), _rule("tcp", None, ["10.0.0.0/16"])]),
                _server("synthetic-vault", "vault", [_rule("udp", 41641, ["0.0.0.0/0", "::/0"])], networks=False),
            ]
        )

    def test_sources_are_classified_by_trust(self) -> None:
        self.assertEqual(classify_source("0.0.0.0/0", ()), "world")
        self.assertEqual(classify_source("104.16.0.0/13", ()), "cloudflare")
        self.assertEqual(classify_source("100.64.0.0/10", ()), "tailscale")
        self.assertEqual(classify_source("203.0.113.7/32", ()), "allowlist")

    def test_exposure_levels(self) -> None:
        servers = {item["name"]: item for item in build_topology(self.snapshot)["servers"]}
        self.assertEqual(servers["synthetic-edge"]["exposure"], "proxied")
        self.assertEqual(servers["synthetic-db"]["exposure"], "critical")
        self.assertEqual(servers["synthetic-vault"]["exposure"], "private")
        self.assertIn("tailscale", servers["synthetic-vault"]["ingress"])
        self.assertEqual(servers["synthetic-vault"]["networks"], [])

    def test_renderers_never_print_public_addresses(self) -> None:
        topology = build_topology(self.snapshot)
        for output in (render_mermaid(topology), render_svg(topology), render_topology_markdown(topology)):
            self.assertNotIn("192.0.2.10", output)
            self.assertNotIn("173.245.48.0", output)
        self.assertIn("flowchart LR", render_mermaid(topology))
        self.assertTrue(render_svg(topology).startswith("<svg"))
        self.assertIn("#f4f4f4", render_svg(topology))
        self.assertIn("#0b1220", render_svg(topology, theme="dark"))

    def test_svg_is_well_formed_xml_with_special_characters(self) -> None:
        import xml.dom.minidom

        self.snapshot.assets.append(_server("a&b<c>", "edge", [_rule("tcp", 443, ["0.0.0.0/0"])]))
        document = xml.dom.minidom.parseString(render_svg(build_topology(self.snapshot)))  # noqa: S318 -- our own output
        self.assertEqual(document.documentElement.tagName, "svg")


if __name__ == "__main__":
    unittest.main()
