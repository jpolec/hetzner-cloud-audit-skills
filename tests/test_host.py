from __future__ import annotations

import json
import unittest
from pathlib import Path

from hetzner_security.analyzers import hunt
from hetzner_security.findings import render_json, render_sarif
from hetzner_security.flows import PortSet
from hetzner_security.graph import AttackGraph
from hetzner_security.host import BUNDLE_SCRIPT, apply_host_bundles, parse_bundle
from hetzner_security.host.parsers import (
    bind_class,
    nftables_allowed,
    parse_nftables,
    parse_ufw,
    pg_remote_decisions,
    ufw_allowed,
)
from hetzner_security.models import Asset, Edge, Finding, Snapshot
from hetzner_security.verification import verify_all

FIXTURES = Path(__file__).parent / "fixtures" / "host"
WORLD = ["0.0.0.0/0", "::/0"]


def _rule(first: int, last: int | None = None, sources: list[str] | None = None, protocol: str = "tcp") -> dict[str, object]:
    return {"direction": "in", "protocol": protocol, "port_from": first, "port_to": last or first, "sources": sources or WORLD}


def _server(name: str, rules: list[dict[str, object]], *, firewall: bool = True) -> Asset:
    return Asset(
        f"hcloud:server:{name}", "server", name,
        {"public_ip": True, "firewall_attached": firewall, "inbound": rules if firewall else []},
        {"environment": "production"}, "hcloud_api",
    )


def _bundle(server: str, *, ufw: str, listeners: str, sshd: str = "passwordauthentication no\n") -> str:
    return (
        "hetzner-audit-host-bundle 1\n===HETZNER-AUDIT meta===\nserver=" + server
        + "\n===HETZNER-AUDIT ufw===\n" + ufw
        + "\n===HETZNER-AUDIT nftables===\nnot installed\n===HETZNER-AUDIT docker_user===\nnot installed"
        + "\n===HETZNER-AUDIT listeners===\n" + listeners
        + "\n===HETZNER-AUDIT sshd===\n" + sshd
        + "\n===HETZNER-AUDIT docker===\nnot installed\n===HETZNER-AUDIT pg_hba===\nnot found"
        + "\n===HETZNER-AUDIT redis===\nnot installed\n===HETZNER-AUDIT end===\n"
    )


UFW_DENY = "Status: active\nDefault: deny (incoming), allow (outgoing)\n\nTo  Action  From\n--  ------  ----\n"
UFW_SSH = UFW_DENY + "22/tcp                     ALLOW IN    Anywhere\n"
LISTEN_SSH_PG = (
    'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
    'tcp LISTEN 0 128 0.0.0.0:5432 0.0.0.0:* users:(("postgres",pid=2,fd=3))\n'
)


def _merge(snapshot: Snapshot, *bundles: tuple[str, str], tmp: Path) -> Snapshot:
    paths = []
    for name, text in bundles:
        path = tmp / f"{name}.bundle"
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    return apply_host_bundles(snapshot, paths)


def _findings(snapshot: Snapshot) -> list[Finding]:
    return verify_all(hunt(snapshot), snapshot)


def _by_rule(findings: list[Finding], rule_id: str) -> list[Finding]:
    return [item for item in findings if item.rule_id == rule_id]


class ParserTest(unittest.TestCase):
    def test_ufw_first_match_with_private_and_interface_rules(self) -> None:
        text = (FIXTURES / "app-1.bundle").read_text()
        parsed = parse_bundle(text)
        ufw = parsed["ufw"]
        self.assertTrue(ufw["active"])
        self.assertEqual(ufw_allowed(ufw, "tcp", "0.0.0.0/0"), PortSet())
        self.assertEqual(ufw_allowed(ufw, "udp", "0.0.0.0/0"), PortSet.of([(51820, 51820)]))
        self.assertEqual(ufw_allowed(ufw, "tcp", "10.0.0.0/16"), PortSet.full())

    def test_ufw_deny_before_allow_wins_and_app_profiles(self) -> None:
        text = UFW_DENY + "5432/tcp  DENY IN  Anywhere\nAnywhere  ALLOW IN  Anywhere\nOpenSSH on eth0  ALLOW IN  Anywhere\n"
        allowed = ufw_allowed(parse_ufw(text), "tcp", "0.0.0.0/0")
        self.assertNotIn(5432, allowed or PortSet())
        self.assertIn(22, allowed or PortSet())

    def test_nftables_policy_drop_and_jump(self) -> None:
        drop = "table inet filter {\n chain input {\n  type filter hook input priority 0; policy drop;\n  ct state established,related accept\n  iifname \"lo\" accept\n  tcp dport { 22, 443 } accept\n  ip saddr 10.0.0.0/8 tcp dport 5432 accept\n }\n}"
        allowed = nftables_allowed(parse_nftables(drop), "tcp", "0.0.0.0/0")
        self.assertEqual(allowed, PortSet.of([(22, 22), (443, 443)]))
        jump = "table inet filter {\n chain input {\n  type filter hook input priority 0; policy accept;\n  jump ufw-before-input\n }\n}"
        self.assertIsNone(nftables_allowed(parse_nftables(jump), "tcp", "0.0.0.0/0"))

    def test_bind_classes(self) -> None:
        self.assertEqual(bind_class("0.0.0.0"), "wildcard")
        self.assertEqual(bind_class("[::]"), "wildcard")
        self.assertEqual(bind_class("127.0.0.53%lo"), "loopback")
        self.assertEqual(bind_class("100.64.0.7"), "internal")
        self.assertEqual(bind_class("203.0.113.9"), "public")

    def test_pg_hba_first_match_reject_shadows_trust(self) -> None:
        entries = parse_bundle((FIXTURES / "db-1.bundle").read_text())["pg_hba"]["files"]["/etc/postgresql/16/main/pg_hba.conf"]
        decisions = pg_remote_decisions(entries)
        self.assertEqual([entry["method"] for entry in decisions], ["md5"])

    def test_redis_secrets_never_leave_the_host(self) -> None:
        self.assertIn("<set>", BUNDLE_SCRIPT)
        self.assertIn("#<redacted>", BUNDLE_SCRIPT)
        self.assertNotIn(".Config.Env", BUNDLE_SCRIPT)

    def test_rejects_non_bundle_input(self) -> None:
        with self.assertRaises(ValueError):
            parse_bundle("root:x:0:0:root:/root:/bin/bash\n")


class HostEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self._dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._dir.name)

    def tearDown(self) -> None:
        self._dir.cleanup()

    def test_docker_bypass_behind_cloud_firewall_is_medium(self) -> None:
        server = _server("app-1", [_rule(443), _rule(9001, sources=["203.0.113.0/24"])])
        snapshot = apply_host_bundles(Snapshot(assets=[server]), [FIXTURES / "app-1.bundle"])
        findings = _findings(snapshot)
        bypass = _by_rule(findings, "HETZ-DKR-005")
        self.assertEqual(len(bypass), 1)
        self.assertEqual(bypass[0].status.value, "confirmed")
        self.assertEqual(bypass[0].severity.value if bypass[0].severity else None, "medium")
        self.assertIn("9001", bypass[0].actual_state)
        self.assertNotIn("4100", bypass[0].actual_state)  # Tailscale and loopback binds are not a bypass
        # The cAdvisor container: privileged, Docker socket, and host root mounts.
        for rule in ("HETZ-DKR-001", "HETZ-DKR-002", "HETZ-DKR-006"):
            self.assertTrue(_by_rule(findings, rule), rule)
        self.assertFalse(_by_rule(findings, "HETZ-SSH-001"))
        json.loads(render_json(findings))
        json.loads(render_sarif(findings))

    def test_docker_bypass_open_in_cloud_is_high_and_reachable(self) -> None:
        server = _server("app-1", [_rule(9001)])
        edge = Edge("internet", server.id, "allows", "tcp", 9001)  # as the collector derives it
        snapshot = apply_host_bundles(Snapshot(assets=[server], edges=[edge]), [FIXTURES / "app-1.bundle"])
        bypass = _by_rule(_findings(snapshot), "HETZ-DKR-005")
        self.assertEqual(bypass[0].severity.value if bypass[0].severity else None, "high")
        path = AttackGraph(snapshot).explain_path("internet", "hcloud:server:app-1", protocol="tcp", port=9001)
        self.assertEqual(path["result"], "reachable")
        self.assertTrue(AttackGraph(snapshot).reachable("internet", "host:container:app-1:api-app", protocol="tcp", port=9001))

    def test_host_firewall_rejects_cloud_only_exposure(self) -> None:
        server = _server("web-1", [_rule(5432)])
        snapshot = _merge(Snapshot(assets=[server]), ("web-1", _bundle("web-1", ufw=UFW_SSH, listeners=LISTEN_SSH_PG)), tmp=self.tmp)
        net = _by_rule(_findings(snapshot), "HETZ-NET-003")
        self.assertEqual(net[0].status.value, "rejected")
        self.assertIn("host", net[0].verification.notes)

    def test_complete_host_evidence_confirms_exposure(self) -> None:
        server = _server("web-1", [_rule(22)])
        snapshot = _merge(Snapshot(assets=[server]), ("web-1", _bundle("web-1", ufw=UFW_SSH, listeners=LISTEN_SSH_PG)), tmp=self.tmp)
        net = _by_rule(_findings(snapshot), "HETZ-NET-001")
        self.assertEqual(net[0].status.value, "confirmed")

    def test_nothing_listening_rejects_exposure(self) -> None:
        server = _server("web-1", [_rule(22)])
        listeners = 'tcp LISTEN 0 128 127.0.0.1:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))\n'
        snapshot = _merge(Snapshot(assets=[server]), ("web-1", _bundle("web-1", ufw=UFW_SSH, listeners=listeners)), tmp=self.tmp)
        self.assertEqual(_by_rule(_findings(snapshot), "HETZ-NET-001")[0].status.value, "rejected")

    def test_database_host_without_any_firewall(self) -> None:
        server = _server("db-1", [], firewall=False)
        snapshot = apply_host_bundles(Snapshot(assets=[server]), [FIXTURES / "db-1.bundle"])
        findings = _findings(snapshot)
        ids = {item.rule_id for item in findings if item.status.value == "confirmed"}
        for rule in ("HETZ-HOST-001", "HETZ-SSH-001", "HETZ-SSH-002", "HETZ-HOST-002", "HETZ-PG-003", "HETZ-RDS-001"):
            self.assertIn(rule, ids)
        self.assertFalse(_by_rule(findings, "HETZ-PG-001"))  # the trust line is shadowed by an earlier reject
        host_fw = _by_rule(findings, "HETZ-HOST-001")[0]
        self.assertEqual(host_fw.severity.value if host_fw.severity else None, "high")

    def test_unmatched_bundle_is_reported_not_guessed(self) -> None:
        snapshot = apply_host_bundles(Snapshot(assets=[_server("other", [])]), [FIXTURES / "db-1.bundle"])
        self.assertEqual(snapshot.metadata["host_bundles"][0]["status"], "unmatched")
        self.assertFalse([asset for asset in snapshot.assets if asset.source == "host_bundle"])

    def test_without_bundle_host_rules_are_silent(self) -> None:
        ids = {item.rule_id for item in _findings(Snapshot(assets=[_server("db-1", [], firewall=False)]))}
        self.assertFalse(ids & {"HETZ-HOST-001", "HETZ-SSH-001", "HETZ-DKR-005", "HETZ-HOST-002"})

    def test_cli_accepts_host_bundle(self) -> None:
        from hetzner_security.cli.main import build_parser, run

        snapshot = Snapshot(assets=[_server("app-1", [_rule(443)])])
        source = self.tmp / "snap.json"
        source.write_text(json.dumps(snapshot.to_dict()))
        out = self.tmp / "audit.json"
        args = build_parser().parse_args(
            ["audit", "--input", str(source), "--host-bundle", str(FIXTURES / "app-1.bundle"), "--format", "json", "--output", str(out)]
        )
        self.assertEqual(run(args), 0)
        self.assertIn("HETZ-DKR-005", out.read_text())


if __name__ == "__main__":
    unittest.main()


class PrivateNetworkReachTest(unittest.TestCase):
    def test_unauthenticated_redis_reachable_over_private_network_is_confirmed(self) -> None:
        # The Cloud Firewall blocks the Internet, but private networks are unfiltered and the host firewall is off.
        server = _server("db-1", [_rule(443)])
        server.properties["private_net"] = [{"network": 7, "ip": "10.0.0.5"}]
        network = Asset("hcloud:network:7", "network", "core", {"ip_range": "10.0.0.0/16"}, {}, "hcloud_api")
        peer = Asset("hcloud:server:peer", "server", "peer", {"private_net": [{"network": 7}]}, {}, "hcloud_api")
        edges = [Edge("hcloud:server:peer", "hcloud:network:7", "attached_to")]
        snapshot = apply_host_bundles(Snapshot(assets=[server, network, peer], edges=edges), [FIXTURES / "db-1.bundle"])
        statuses = {item.rule_id: item.status.value for item in _findings(snapshot)}
        self.assertEqual(statuses["HETZ-RDS-001"], "confirmed")
        self.assertEqual(statuses["HETZ-PG-003"], "confirmed")
        self.assertNotIn("HETZ-NET-004", statuses)  # nothing is open to the Internet

    def test_tailscale_bind_is_not_on_the_hetzner_private_network(self) -> None:
        server = _server("app-1", [_rule(443)])
        server.properties["private_net"] = [{"network": 7, "ip": "10.0.0.9"}]
        network = Asset("hcloud:network:7", "network", "core", {"ip_range": "10.0.0.0/16"}, {}, "hcloud_api")
        snapshot = apply_host_bundles(Snapshot(assets=[server, network]), [FIXTURES / "app-1.bundle"])
        private = snapshot.asset_map()["hcloud:server:app-1"].properties["private_listening_ports"]
        self.assertNotIn(4100, private)  # bound to 100.64.0.7 (Tailscale) and loopback only
        self.assertIn(9001, private)  # Docker publishes on all interfaces
