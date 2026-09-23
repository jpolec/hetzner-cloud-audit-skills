from __future__ import annotations

import unittest

from hetzner_security.diagram import render_connectivity_svg, render_cost_svg, render_svg
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

    def test_connectivity_and_cost_views_render_without_public_addresses(self) -> None:
        import xml.dom.minidom

        topology = build_topology(self.snapshot)
        cost = {
            "currency": "EUR",
            "current_catalog_estimate": {"monthly_net": 30.0},
            "identified_potential_savings": {"monthly_net": 5.0, "annual_net": 60.0, "confirmed_monthly_net": 0.0},
            "servers": [
                {"asset_id": item["id"], "name": item["name"], "status": "running", "server_type": "cx23", "cores": 2, "memory_gb": 4, "monthly_net": 10.0, "components_net": {"server": 9.5, "ipv4": 0.5}}
                for item in topology["servers"]
            ],
            "recommendations": [
                {"rule_id": "HETZ-COST-002", "assets": [topology["servers"][0]["id"]], "candidate_state": {"server_type": "cx22"}, "estimated_savings": {"monthly": 5.0}}
            ],
            "resource_components_net": {},
        }
        for output in (render_connectivity_svg(topology), render_cost_svg(topology, cost)):
            xml.dom.minidom.parseString(output)  # noqa: S318 -- our own output
            self.assertNotIn("192.0.2.10", output)
        connectivity = render_connectivity_svg(topology)
        self.assertIn("do not filter private networks", connectivity)
        self.assertIn("reachable from 1 VM<", connectivity)
        self.assertIn("cx22", render_cost_svg(topology, cost))

    def test_svg_is_well_formed_xml_with_special_characters(self) -> None:
        import xml.dom.minidom

        self.snapshot.assets.append(_server("a&b<c>", "edge", [_rule("tcp", 443, ["0.0.0.0/0"])]))
        document = xml.dom.minidom.parseString(render_svg(build_topology(self.snapshot)))  # noqa: S318 -- our own output
        self.assertEqual(document.documentElement.tagName, "svg")


if __name__ == "__main__":
    unittest.main()
