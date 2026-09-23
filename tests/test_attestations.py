from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from hetzner_security.actions import evidence_level
from hetzner_security.analyzers import hunt
from hetzner_security.attestations import apply_attestations, load_attestations, template
from hetzner_security.models import Snapshot
from hetzner_security.verification import verify_all


class AttestationTest(unittest.TestCase):
    def _findings(self, answers: dict[str, object]) -> dict[str, tuple[str, str]]:
        raw = {**template(), "answered_by": "owner", "date": "2026-09-23", "answers": answers}
        snapshot = apply_attestations(Snapshot(), raw, "answers.json")
        return {item.rule_id: (item.status.value, evidence_level(item)[0]) for item in verify_all(hunt(snapshot), snapshot)}

    def test_no_is_confirmed_unknown_needs_validation_yes_is_clean(self) -> None:
        found = self._findings({"console_2fa_all_members": False, "api_tokens_reviewed": "unknown", "robot_account_protected": True})
        self.assertEqual(found["HETZ-ATT-001"], ("confirmed", "MEDIUM"))
        self.assertEqual(found["HETZ-ATT-003"], ("needs_validation", "LOW"))
        self.assertNotIn("HETZ-ATT-004", found)
        self.assertNotIn("HETZ-ATT-002", found)  # not asked: no finding

    def test_template_round_trip_and_unknown_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "answers.json"
            path.write_text(json.dumps(template()))
            self.assertEqual(len(load_attestations(path)["answers"]), 7)
            path.write_text(json.dumps({"answers": {"made_up": True}}))
            with self.assertRaises(ValueError):
                load_attestations(path)


if __name__ == "__main__":
    unittest.main()
