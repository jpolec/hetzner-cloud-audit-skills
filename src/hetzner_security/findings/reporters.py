"""Render verified records without changing verdict, impact, or severity."""

from __future__ import annotations

import json
from typing import Any

from ..models import Finding, FindingStatus


def render_json(findings: list[Finding]) -> str:
    return json.dumps({"schema_version": "1.0.0", "findings": [f.to_dict() for f in findings]}, indent=2)


def render_markdown(findings: list[Finding]) -> str:
    lines = ["# Hetzner Security Audit", ""]
    confirmed = [finding for finding in findings if finding.status == FindingStatus.CONFIRMED]
    pending = [finding for finding in findings if finding.status == FindingStatus.NEEDS_VALIDATION]
    rejected = [finding for finding in findings if finding.status == FindingStatus.REJECTED]
    lines.extend(
        [
            "## Summary",
            "",
            f"- Confirmed: {len(confirmed)}",
            f"- Needs validation: {len(pending)}",
            f"- Rejected: {len(rejected)}",
            "",
        ]
    )
    for finding in [*confirmed, *pending]:
        lines.extend(
            [
                f"## {finding.severity.value.upper()} · {finding.rule_id} · {finding.title}",
                "",
                f"**Status:** {finding.status.value}  ",
                f"**Confidence:** {finding.confidence:.2f}  ",
                f"**Assets:** {', '.join(finding.assets)}",
                "",
                "**Observation:** " + finding.observation,
                "",
                "**Expected:** " + finding.expected_state,
                "",
                "**Actual:** " + finding.actual_state,
                "",
                "**Attack path:** " + " → ".join(finding.attack_path),
                "",
                "**Verification:** " + finding.verification.notes,
                "",
                "**Impact:** " + finding.impact,
                "",
                "**Remediation:** " + finding.remediation,
                "",
            ]
        )
    return "\n".join(lines)


def render_sarif(findings: list[Finding]) -> str:
    active = [finding for finding in findings if finding.status != FindingStatus.REJECTED]
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in active:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "shortDescription": {"text": finding.title},
                "helpUri": finding.references[0] if finding.references else None,
            },
        )
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": level[finding.severity.value],
                "message": {"text": f"{finding.status.value}: {finding.observation}"},
                "properties": {
                    "confidence": finding.confidence,
                    "status": finding.status.value,
                    "assets": finding.assets,
                },
            }
        )
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "hetzner-security-skills",
                        "version": "0.1.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2)

