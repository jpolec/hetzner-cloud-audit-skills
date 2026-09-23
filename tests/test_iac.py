from __future__ import annotations

import unittest
from pathlib import Path

from hetzner_security.analyzers import hunt
from hetzner_security.iac import apply_terraform, load_terraform
from hetzner_security.models import Asset, Snapshot
from hetzner_security.verification import verify_all

FIXTURES = Path(__file__).parent / "fixtures" / "terraform"
WORLD = ["0.0.0.0/0", "::/0"]


def _snapshot(ssh_sources: list[str], *, protection: bool = True, extra_firewall: bool = False) -> Snapshot:
    assets = [
        Asset("hcloud:firewall:101", "firewall", "web", {"inbound": [
            {"direction": "in", "protocol": "tcp", "port_from": 443, "port_to": 443, "sources": WORLD},
            {"direction": "in", "protocol": "tcp", "port_from": 22, "port_to": 22, "sources": ssh_sources},
        ], "applied_to": []}, {}, "hcloud_api"),
        Asset("hcloud:server:11", "server", "web-1", {
            "server_type": {"name": "cx22"}, "protection": {"delete": protection, "rebuild": True},
            "backup_enabled": True, "firewall_ids": [101], "public_ip": True, "firewall_attached": True,
        }, {"environment": "production", "role": "web"}, "hcloud_api"),
    ]
    if extra_firewall:
        assets.append(Asset("hcloud:firewall:202", "firewall", "manual", {"inbound": [], "applied_to": []}, {}, "hcloud_api"))
    return Snapshot(assets=assets)


def _rules(snapshot: Snapshot) -> dict[str, list[str]]:
    output: dict[str, list[str]] = {}
    for finding in verify_all(hunt(apply_terraform(snapshot, FIXTURES / "state.json")), apply_terraform(snapshot, FIXTURES / "state.json")):
        if finding.rule_id.startswith("HETZ-IAC-"):
            output.setdefault(finding.rule_id, []).append(finding.status.value)
    return output


class TerraformDriftTest(unittest.TestCase):
    def test_loader_walks_child_modules_and_skips_data_sources(self) -> None:
        state = load_terraform(FIXTURES / "state.json")
        self.assertEqual(sorted(item["address"] for item in state["resources"]),
                         ["hcloud_firewall.web", "hcloud_server.gone", "module.app.hcloud_server.web"])

    def test_clean_state_reports_only_the_deleted_server(self) -> None:
        rules = _rules(_snapshot(["100.64.0.0/10"]))
        self.assertEqual(rules, {"HETZ-IAC-003": ["needs_validation"]})

    def test_widened_ssh_source_is_iac_001(self) -> None:
        rules = _rules(_snapshot(["100.64.0.0/10", "0.0.0.0/0"]))
        self.assertEqual(rules.get("HETZ-IAC-001"), ["needs_validation"])  # a state file may be stale

    def test_protection_drift_and_unmanaged_firewall(self) -> None:
        rules = _rules(_snapshot(["100.64.0.0/10"], protection=False, extra_firewall=True))
        self.assertEqual(rules.get("HETZ-IAC-004"), ["needs_validation"])
        self.assertEqual(rules.get("HETZ-IAC-002"), ["needs_validation"])

    def test_saved_plan_lists_security_changes(self) -> None:
        snapshot = apply_terraform(_snapshot(["100.64.0.0/10"]), FIXTURES / "plan.json")
        self.assertEqual(snapshot.metadata["terraform"]["kind"], "plan")
        findings = [item for item in hunt(snapshot) if item.rule_id == "HETZ-IAC-005"]
        self.assertEqual(len(findings), 1)
        self.assertIn("hcloud_server.web: delete/create", findings[0].actual_state)

    def test_saved_plan_compares_runtime_with_planned_values(self) -> None:
        # Runtime SSH is open to the world; the plan (configuration) restricts it: confirmed drift.
        snapshot = apply_terraform(_snapshot(["100.64.0.0/10", "0.0.0.0/0"]), FIXTURES / "plan.json")
        found = {item.rule_id: item.status.value for item in verify_all(hunt(snapshot), snapshot)}
        self.assertEqual(found.get("HETZ-IAC-001"), "confirmed")

    def test_malformed_terraform_is_a_clean_error(self) -> None:
        path = FIXTURES.parent / "bad-terraform.json"
        path.write_text('{"format_version": "1.0", "values": {"root_module": {"resources": ["x"]}}}')
        try:
            with self.assertRaises(ValueError):
                load_terraform(path)
        finally:
            path.unlink()

    def test_rejects_non_terraform_json(self) -> None:
        path = FIXTURES.parent / "not-terraform.json"
        path.write_text("{}")
        try:
            with self.assertRaises(ValueError):
                load_terraform(path)
        finally:
            path.unlink()


if __name__ == "__main__":
    unittest.main()
