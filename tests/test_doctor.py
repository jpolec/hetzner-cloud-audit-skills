from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from hetzner_security.collectors.hcloud import HCloudCollectionError
from hetzner_security.doctor import render_doctor_markdown, run_doctor

TOKEN = "fixture-token-must-never-be-printed"  # noqa: S105


def _probe(failures: dict[str, int] | None = None):  # type: ignore[no-untyped-def]
    def probe(endpoint: str, base_url: str | None) -> dict[str, Any]:
        status = (failures or {}).get(endpoint)
        if status:
            raise HCloudCollectionError(f"HTTP {status}", status=status)
        return {endpoint: [], "meta": {"pagination": {"total_entries": 3}}}

    return probe


class DoctorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _status(self, result: dict[str, Any], name: str) -> str:
        return next(item["status"] for item in result["checks"] if item["name"] == name)

    def test_missing_token_fails_without_api_calls(self) -> None:
        def forbidden_probe(endpoint: str, base_url: str | None) -> dict[str, Any]:
            raise AssertionError("no API call expected without a token")

        result = run_doctor(env={}, report_dir=self.dir, probe=forbidden_probe, which=lambda _: None)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(self._status(result, "Token"), "fail")

    def test_healthy_run_reports_scope_and_never_prints_token(self) -> None:
        result = run_doctor(env={"HCLOUD_TOKEN": TOKEN}, report_dir=self.dir, probe=_probe(), which=lambda _: "/bin/x")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["scope"]["server"], 3)
        self.assertEqual(set(result["endpoints"].values()), {"ok"})
        for output in (render_doctor_markdown(result), json.dumps(result)):
            self.assertNotIn(TOKEN, output)

    def test_rejected_token_fails(self) -> None:
        result = run_doctor(env={"HCLOUD_TOKEN": TOKEN}, report_dir=self.dir, probe=_probe({"servers": 401}), which=lambda _: None)
        self.assertEqual(self._status(result, "API access"), "fail")

    def test_unavailable_optional_endpoint_warns_but_core_failure_fails(self) -> None:
        optional = run_doctor(env={"HCLOUD_TOKEN": TOKEN}, report_dir=self.dir, probe=_probe({"storage_boxes": 404}), which=lambda _: None)
        self.assertEqual(self._status(optional, "Endpoint coverage"), "warn")
        core = run_doctor(env={"HCLOUD_TOKEN": TOKEN}, report_dir=self.dir, probe=_probe({"firewalls": 403}), which=lambda _: None)
        self.assertEqual(self._status(core, "Endpoint coverage"), "fail")

    def test_token_in_dotenv_warns(self) -> None:
        (self.dir / ".env").write_text("HCLOUD_TOKEN=abc\n")
        result = run_doctor(env={}, report_dir=self.dir, which=lambda _: None)
        self.assertEqual(self._status(result, "Token storage"), "warn")


if __name__ == "__main__":
    unittest.main()
