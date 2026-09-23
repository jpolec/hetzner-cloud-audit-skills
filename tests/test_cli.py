from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from hetzner_security.cli.main import build_parser, run

ROOT = Path(__file__).resolve().parents[1]


class SuppressionTest(unittest.TestCase):
    def test_audit_ignore_labels_suppress_visibly(self) -> None:
        import tempfile

        snapshot = {"assets": [
            {"id": "a", "type": "server", "name": "tmp-build", "source": "hcloud_api",
             "labels": {"environment": "production", "audit.ignore.HETZ-BCP-001": "true"},
             "properties": {"stateful": True, "backup_enabled": False}},
            {"id": "b", "type": "server", "name": "scratch", "source": "hcloud_api",
             "labels": {"audit.ignore": "true"}, "properties": {}},
        ]}
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "s.json"
            source.write_text(json.dumps(snapshot))
            report = Path(directory) / "audit.md"
            run(build_parser().parse_args(["audit", "--input", str(source), "--format", "markdown", "--output", str(report)]))
            text = report.read_text()
            data = Path(directory) / "audit.json"
            run(build_parser().parse_args(["audit", "--input", str(source), "--format", "json", "--output", str(data)]))
            findings = json.loads(data.read_text())["findings"]
        self.assertNotIn("HETZ-BCP-001", {item["rule_id"] for item in findings})
        self.assertFalse([item for item in findings if item["assets"] == ["b"]])
        self.assertIn("Suppressed by owner labels (`audit.ignore`)", text)
        self.assertIn("HETZ-BCP-001", text.split("Suppressed by owner labels (`audit.ignore`)")[1])


class CliTest(unittest.TestCase):
    def test_fail_on_counts_only_confirmed_findings(self) -> None:
        fixture = str(Path(__file__).parents[1] / "benchmarks" / "scenarios" / "v0.1-insecure.json")
        base = ["audit", "--input", fixture, "--format", "json", "--output", "/dev/null"]
        self.assertEqual(run(build_parser().parse_args(base)), 0)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(run(build_parser().parse_args([*base, "--fail-on", "confirmed-high"])), 1)
        # A snapshot with only needs_validation findings never fails.
        snapshot = {"assets": [{"id": "s", "type": "server", "name": "db", "labels": {"environment": "production"},
                                "properties": {"stateful": True, "backup_enabled": False}}]}
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(snapshot, handle)
        args = ["audit", "--input", handle.name, "--format", "json", "--output", "/dev/null", "--fail-on", "confirmed"]
        self.assertEqual(run(build_parser().parse_args(args)), 0)

    def test_coverage_can_render_to_stdout_without_writing(self) -> None:
        args = build_parser().parse_args(
            [
                "coverage",
                "--input",
                str(ROOT / "benchmarks/scenarios/v0.1-insecure.json"),
                "--read-only",
                "--no-ssh",
                "--no-external-tools",
            ]
        )
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(run(args), 0)
        ledger = json.loads(output.getvalue())
        self.assertEqual(len(ledger), 34)
        self.assertTrue(all("prior_status" in item for item in ledger))


if __name__ == "__main__":
    unittest.main()
