"""Regressions from the adversarial review: unknown host evidence must never reject or confirm."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hetzner_security.analyzers import hunt
from hetzner_security.flows import PortSet
from hetzner_security.host import apply_host_bundles
from hetzner_security.host.parsers import (
    nftables_allowed,
    parse_nftables,
    parse_ufw,
    pg_remote_decisions,
    ufw_allowed,
)
from hetzner_security.models import Asset, Snapshot
from hetzner_security.verification import verify_all

WORLD = ["0.0.0.0/0", "::/0"]
PG_LISTEN = 'tcp LISTEN 0 128 0.0.0.0:5432 0.0.0.0:* users:(("postgres",pid=2,fd=3))'


def _bundle(**sections: str) -> str:
    defaults = {"ufw": "not installed", "nftables": "not installed", "iptables": "not installed", "ip6tables": "not installed",
                "docker_user": "not installed", "listeners": PG_LISTEN, "sshd": "", "docker": "not installed",
                "pg_hba": "not found", "redis": "not installed"}
    defaults.update(sections)
    body = "".join(f"===HETZNER-AUDIT {name}===\n{value}\n" for name, value in defaults.items())
    return f"hetzner-audit-host-bundle 1\n===HETZNER-AUDIT meta===\nserver=db-1\n{body}===HETZNER-AUDIT end===\n"


def _status(bundle: str, rule: str = "HETZ-NET-003") -> str | None:
    server = Asset("hcloud:server:db-1", "server", "db-1", {"public_ip": True, "firewall_attached": True, "inbound": [
        {"direction": "in", "protocol": "tcp", "port_from": 5432, "port_to": 5432, "sources": WORLD}]}, {}, "hcloud_api")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "db-1.bundle"
        path.write_text(bundle)
        snapshot = apply_host_bundles(Snapshot(assets=[server]), [path])
    found = [item.status.value for item in verify_all(hunt(snapshot), snapshot) if item.rule_id == rule]
    return found[0] if found else None


UFW_HEAD = "Status: active\nDefault: deny (incoming), allow (outgoing)\n\nTo                         Action      From\n--                         ------      ----\n"


class UnknownIsNotRejectedTest(unittest.TestCase):
    def test_unreadable_or_missing_layers_stay_needs_validation(self) -> None:
        cases = {
            "ufw without root": {"ufw": "ERROR: You need to be root to run this script"},
            "firewalld jump": {"nftables": "table inet firewalld {\n chain filter_INPUT {\n  type filter hook input priority 10; policy accept;\n  jump filter_INPUT_ZONES\n }\n}"},
            "no ss": {"listeners": "not installed"},
            "nft without root": {"nftables": "netlink: Error: cache initialization failed: Operation not permitted"},
            "custom ufw app profile": {"ufw": UFW_HEAD + "PostgreSQL                 ALLOW IN    Anywhere\n"},
            "unknown interface": {"ufw": UFW_HEAD + "5432/tcp on bond0          ALLOW IN    Anywhere\n"},
        }
        for name, sections in cases.items():
            self.assertEqual(_status(_bundle(**sections)), "needs_validation", name)

    def test_readable_accepts_confirm(self) -> None:
        cases = {
            "ufw on eth0": {"ufw": UFW_HEAD + "5432/tcp on eth0           ALLOW IN    Anywhere\n"},
            "nft comment": {"nftables": 'table inet f {\n chain input {\n  type filter hook input priority 0; policy drop;\n  tcp dport 5432 accept comment "db"\n }\n}'},
            "iptables legacy": {"nftables": "", "iptables": "-P INPUT DROP\n-A INPUT -p tcp -m tcp --dport 5432 -j ACCEPT",
                                "ip6tables": "-P INPUT DROP"},
        }
        for name, sections in cases.items():
            self.assertEqual(_status(_bundle(**sections)), "confirmed", name)

    def test_empty_nft_and_accepting_iptables_is_no_firewall(self) -> None:
        bundle = _bundle(nftables="", iptables="-P INPUT ACCEPT", ip6tables="-P INPUT ACCEPT")
        self.assertEqual(_status(bundle, "HETZ-HOST-001"), "confirmed")
        self.assertIsNone(_status(_bundle(), "HETZ-HOST-001"))  # nothing observed: no claim either way


class ParserSemanticsTest(unittest.TestCase):
    def test_nft_matches(self) -> None:
        def allowed(rule: str) -> PortSet | None:
            text = f"table inet f {{\n chain input {{\n  type filter hook input priority 0; policy drop;\n  {rule}\n }}\n}}"
            return nftables_allowed(parse_nftables(text), "tcp", "0.0.0.0/0")

        self.assertEqual(allowed("tcp dport 5432 ct state new accept"), PortSet.of([(5432, 5432)]))
        self.assertEqual(allowed("ip protocol icmp accept"), PortSet())
        self.assertEqual(allowed("meta nfproto ipv6 tcp dport 5432 accept"), PortSet())
        self.assertIsNone(allowed("ip saddr @blocklist drop"))

    def test_ufw_families_are_separate(self) -> None:
        parsed = parse_ufw(UFW_HEAD + "5432/tcp (v6)              ALLOW IN    Anywhere (v6)\n")
        self.assertEqual(ufw_allowed(parsed, "tcp", "0.0.0.0/0"), PortSet())
        self.assertEqual(ufw_allowed(parsed, "tcp", "::/0"), PortSet.of([(5432, 5432)]))

    def test_pg_reject_shadows_only_what_it_covers(self) -> None:
        def decisions(first: tuple[str, str], second: tuple[str, str]) -> list[str]:
            entries = [{"type": first[0], "database": "all", "user": "all", "address": first[1], "method": "reject"},
                       {"type": second[0], "database": "all", "user": "all", "address": second[1], "method": "trust"}]
            return [entry["type"] for entry in pg_remote_decisions(entries)]

        self.assertEqual(decisions(("hostnossl", "0.0.0.0/0"), ("hostssl", "0.0.0.0/0")), ["hostssl"])
        self.assertEqual(decisions(("host", "0.0.0.0/0"), ("host", "::/0")), ["host"])
        self.assertEqual(decisions(("host", "0.0.0.0/0"), ("hostssl", "0.0.0.0/0")), [])


if __name__ == "__main__":
    unittest.main()


class UnknownIsShownAsUnknownTest(unittest.TestCase):
    def test_summary_topology_and_views_say_unknown(self) -> None:
        from hetzner_security.diagram import render_host_svg
        from hetzner_security.findings.summary import build_summary, host_rows
        from hetzner_security.topology import build_topology

        server = Asset("hcloud:server:db-1", "server", "db-1", {"public_ip": True, "firewall_attached": True, "inbound": []}, {}, "hcloud_api")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "db-1.bundle"
            path.write_text(_bundle(ufw="ERROR: You need to be root to run this script"))
            snapshot = apply_host_bundles(Snapshot(assets=[server]), [path])
        row = build_summary(snapshot, [])["host_evidence"][0]
        self.assertEqual(row["reachable"], "unknown")
        self.assertEqual(row["host_firewall_admits"], "unknown")
        self.assertNotIn("filters nothing", row["engine"])
        self.assertEqual(build_topology(snapshot)["servers"][0]["host"]["firewall"], "unknown")
        svg = render_host_svg([{**host_rows(snapshot)[0], "subtitle": "", "containers": []}])
        self.assertIn("could not be read", svg)
