from __future__ import annotations

import unittest

from hetzner_security.analyzers import hunt
from hetzner_security.findings.summary import build_summary
from hetzner_security.models import Asset, Snapshot
from hetzner_security.provider_ranges import EDGE_RANGES
from hetzner_security.providers import edge_provider, is_mesh, mesh_port, tunnel_agents
from hetzner_security.topology import build_topology, classify_source
from hetzner_security.verification import verify_all

WORLD = ["0.0.0.0/0", "::/0"]


def _server(name: str, rules: list[tuple[str, int, list[str]]], **props: object) -> Asset:
    inbound = [{"direction": "in", "protocol": proto, "port_from": port, "port_to": port, "sources": sources} for proto, port, sources in rules]
    return Asset(f"hcloud:server:{name}", "server", name, {"public_ip": True, "firewall_attached": True, "inbound": inbound, **props},
                 {"role": "web"}, "hcloud_api")


def _first_range(key: str, version: int = 4) -> str:
    return next(value for value in EDGE_RANGES[key]["ranges"] if (":" in value) == (version == 6))


class ProviderRegistryTest(unittest.TestCase):
    def test_every_list_is_dated_sourced_and_nonempty(self) -> None:
        for key, entry in EDGE_RANGES.items():
            self.assertTrue(entry["ranges"], key)
            self.assertRegex(str(entry["as_of"]), r"^\d{4}-\d{2}-\d{2}$")
            self.assertTrue(str(entry["source"]).startswith("https://"), key)

    def test_recognition(self) -> None:
        self.assertEqual(edge_provider(_first_range("fastly")), "Fastly")
        self.assertEqual(edge_provider(_first_range("cloudflare", 6)), "Cloudflare")
        self.assertIsNone(edge_provider("0.0.0.0/0"))
        self.assertIsNone(edge_provider("203.0.113.0/24"))
        self.assertTrue(is_mesh("100.64.0.0/10"))
        self.assertEqual(classify_source(_first_range("bunny"), ()), "edge")
        self.assertEqual(mesh_port("udp", 51820), "WireGuard / NetBird")
        self.assertIsNone(mesh_port("tcp", 51820))
        self.assertEqual(tunnel_agents({"host_agents": ["cloudflared"], "listeners": [{"process": "ngrok"}]}), ["Cloudflare Tunnel", "ngrok"])


class EdgeBypassTest(unittest.TestCase):
    def test_bypass_names_the_provider_peers_use(self) -> None:
        fastly = _first_range("fastly")
        snapshot = Snapshot(assets=[_server("cdn-origin", [("tcp", 443, [fastly])]), _server("direct", [("tcp", 443, WORLD)])])
        finding = next(item for item in verify_all(hunt(snapshot), snapshot) if item.rule_id == "HETZ-NET-006")
        self.assertIn("Fastly", finding.title)
        self.assertEqual(finding.status.value, "needs_validation")
        servers = {item["name"]: item for item in build_topology(snapshot)["servers"]}
        self.assertEqual(servers["cdn-origin"]["exposure"], "proxied")
        self.assertEqual(servers["cdn-origin"]["edge_providers"], ["Fastly"])

    def test_no_edge_peers_no_finding(self) -> None:
        snapshot = Snapshot(assets=[_server("a", [("tcp", 443, WORLD)]), _server("b", [("tcp", 443, WORLD)])])
        self.assertNotIn("HETZ-NET-006", {item.rule_id for item in hunt(snapshot)})


class NoIngressTest(unittest.TestCase):
    def test_mesh_only_server_counts_as_no_public_ingress(self) -> None:
        snapshot = Snapshot(assets=[
            _server("vault", [("udp", 41641, WORLD), ("tcp", 22, ["100.64.0.0/10"])], host_agents=["cloudflared"]),
            _server("web", [("tcp", 443, WORLD)]),
        ])
        topology = build_topology(snapshot)
        servers = {item["name"]: item for item in topology["servers"]}
        self.assertTrue(servers["vault"]["no_public_ingress"])
        self.assertFalse(servers["web"]["no_public_ingress"])
        self.assertEqual(servers["vault"]["tunnels"], ["Cloudflare Tunnel"])
        self.assertIn("udp/41641 (Tailscale)", servers["vault"]["ingress"]["mesh"])
        ingress = build_summary(snapshot, [])["ingress"]
        self.assertEqual((ingress["no_public_ingress"], ingress["servers"]), (1, 2))


if __name__ == "__main__":
    unittest.main()
