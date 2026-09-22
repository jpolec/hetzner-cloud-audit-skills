#!/usr/bin/env python3
"""Validate generated benchmark findings and coverage against public schemas."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"


def main() -> None:
    finding_schema = json.loads((SCHEMA_DIR / "finding.schema.json").read_text())
    evidence_schema = json.loads((SCHEMA_DIR / "evidence.schema.json").read_text())
    registry = Registry().with_resource(
        evidence_schema["$id"], Resource.from_contents(evidence_schema)
    )
    validator = Draft202012Validator(finding_schema, registry=registry)
    report = json.loads((ROOT / "examples/reports/demo.json").read_text())
    for index, finding in enumerate(report["findings"]):
        errors = sorted(validator.iter_errors(finding), key=lambda item: list(item.path))
        if errors:
            raise SystemExit(f"finding[{index}]: {errors[0].message}")

    coverage_schema = json.loads((SCHEMA_DIR / "coverage-ledger.schema.json").read_text())
    coverage = json.loads((ROOT / "examples/reports/coverage-ledger.json").read_text())
    Draft202012Validator(coverage_schema).validate(coverage)
    print(f"validated {len(report['findings'])} findings and {len(coverage)} coverage units")


if __name__ == "__main__":
    main()
