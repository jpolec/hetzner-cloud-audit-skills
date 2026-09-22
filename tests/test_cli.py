from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from hetzner_security.cli.main import build_parser, run

ROOT = Path(__file__).resolve().parents[1]


class CliTest(unittest.TestCase):
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
