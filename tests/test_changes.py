from __future__ import annotations

import unittest

from hetzner_security.actions import evidence_level
from hetzner_security.analyzers import hunt
from hetzner_security.collectors.hcloud import _action_signal
from hetzner_security.findings.summary import build_summary
from hetzner_security.models import Asset, Snapshot
from hetzner_security.verification import verify_all


def _action(command: str, server: int = 1, started: str = "2026-09-20T10:00:00Z") -> dict[str, object]:
    return _action_signal(
        {"id": 7, "command": command, "status": "success", "started": started, "finished": started,
         "resources": [{"id": server, "type": "server"}], "error": {"code": "x", "message": "echoes input"}},
        "server",
    )


def _server(protection: bool = True, firewall: bool = True) -> Asset:
    return Asset("hcloud:server:1", "server", "web-1",
                 {"protection": {"delete": protection}, "firewall_attached": firewall, "public_ip": True}, {}, "hcloud_api")


class ChangeSignalTest(unittest.TestCase):
    def test_signal_keeps_error_code_not_message(self) -> None:
        signal = _action("reset_password")
        self.assertEqual(signal["asset_ids"], ["hcloud:server:1"])
        self.assertEqual(signal["error"], "x")
        self.assertNotIn("echoes input", str(signal))

    def test_root_access_actions_need_validation(self) -> None:
        snapshot = Snapshot(assets=[_server()], signals=[_action("enable_rescue"), _action("request_console")],
                            metadata={"coverage": {"actions": {"status": "collected"}}})
        findings = [item for item in verify_all(hunt(snapshot), snapshot) if item.rule_id == "HETZ-CHG-004"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status.value, "needs_validation")
        self.assertEqual(evidence_level(findings[0])[0], "MEDIUM")
        summary = build_summary(snapshot, findings)
        self.assertEqual(summary["changes"]["total"], 2)

    def test_protection_change_reported_only_when_now_off(self) -> None:
        on = Snapshot(assets=[_server(protection=True)], signals=[_action("change_protection")])
        off = Snapshot(assets=[_server(protection=False)], signals=[_action("change_protection")])
        self.assertFalse([item for item in hunt(on) if item.rule_id == "HETZ-CHG-001"])
        self.assertTrue([item for item in hunt(off) if item.rule_id == "HETZ-CHG-001"])

    def test_routine_changes_are_not_findings(self) -> None:
        snapshot = Snapshot(assets=[_server()], signals=[_action("set_firewall_rules"), _action("apply_firewall"), _action("reboot_server")])
        self.assertFalse([item for item in hunt(snapshot) if item.rule_id.startswith("HETZ-CHG-")])

    def test_firewall_removal_on_now_unprotected_server_is_medium(self) -> None:
        snapshot = Snapshot(assets=[_server(firewall=False)], signals=[_action("remove_firewall")])
        finding = next(item for item in hunt(snapshot) if item.rule_id == "HETZ-CHG-002")
        self.assertEqual(finding.severity.value if finding.severity else None, "medium")


if __name__ == "__main__":
    unittest.main()
