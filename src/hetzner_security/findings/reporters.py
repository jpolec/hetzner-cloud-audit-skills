"""Render verified records without changing verdict, impact, or severity."""

from __future__ import annotations

import json
from typing import Any

from ..models import Finding, FindingStatus
from ..text import md
from .summary import render_summary_markdown


def render_json(findings: list[Finding]) -> str:
    return json.dumps({"schema_version": "1.0.0", "findings": [f.to_dict() for f in findings]}, indent=2)


def render_markdown(
    findings: list[Finding],
    metadata: dict[str, Any] | None = None,
    names: dict[str, str] | None = None,
    summary: dict[str, Any] | None = None,
) -> str:
    """Render findings; ``names`` maps asset IDs to display names; ``summary`` adds a first page."""
    lookup = names or {}

    def label(value: str) -> str:
        return md(lookup.get(value, value))

    lines = ["# Hetzner Security Audit", ""]
    confirmed = [finding for finding in findings if finding.status == FindingStatus.CONFIRMED]
    pending = [finding for finding in findings if finding.status == FindingStatus.NEEDS_VALIDATION]
    rejected = [finding for finding in findings if finding.status == FindingStatus.REJECTED]
    if summary is not None:
        lines.extend(render_summary_markdown(summary))
    else:
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
    if metadata:
        lines.extend(
            [
                "## Evidence scope",
                "",
                f"- Collected at: {metadata.get('collected_at', 'unknown')}",
                f"- Collector: {metadata.get('collector', 'normalized snapshot')}",
                f"- Collector version: {metadata.get('collector_version', 'unknown')}",
                f"- Run ID: {metadata.get('run_id', 'unknown')}",
                "",
            ]
        )
        coverage = metadata.get("coverage", {})
        if isinstance(coverage, dict):
            gaps = [
                name
                for name, state in coverage.items()
                if isinstance(state, dict) and state.get("status") not in {"collected", None}
            ]
            lines.extend(
                [
                    "## Collection gaps",
                    "",
                    *(f"- `{name}`: {coverage[name].get('status')}" for name in gaps),
                    *( ["- None reported by the collector."] if not gaps else [] ),
                    "",
                ]
            )
    # Single-asset findings that differ only by asset render as one section to keep reports short.
    groups: dict[tuple[str, ...], list[Finding]] = {}
    for finding in [*confirmed, *pending]:
        key = (
            (finding.rule_id, finding.status.value, finding.observation, finding.actual_state, finding.verification.notes)
            if len(finding.assets) == 1
            else (finding.id,)
        )
        groups.setdefault(key, []).append(finding)
    for members in groups.values():
        finding = members[0]
        assets = [asset for member in members for asset in member.assets]
        if len(members) > 1:
            assets.sort(key=label)
        if len(members) > 1:
            path = " → ".join("each listed asset" if step == finding.assets[0] else label(step) for step in finding.attack_path)
        else:
            path = " → ".join(label(step) for step in finding.attack_path)
        lines.extend(
            [
                f"## {(finding.severity.value.upper() if finding.severity else 'UNSCORED')} · {finding.rule_id} · {md(finding.title)}"
                + (f" ({len(members)} assets)" if len(members) > 1 else ""),
                "",
                f"- **Status:** {finding.status.value}",
                f"- **Confidence:** {min(member.confidence for member in members):.2f}",
                f"- **Assets:** {', '.join(label(asset) for asset in assets)}",
                "",
                "**Observation:** " + md(finding.observation),
                "",
                "**Expected:** " + md(finding.expected_state),
                "",
                "**Actual:** " + md(finding.actual_state),
                "",
                "**Attack path:** " + path,
                "",
                "**Verification:** " + md(finding.verification.notes),
                "",
                "**Impact:** " + md(finding.impact),
                "",
                "**Remediation:** " + md(finding.remediation),
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
                "level": level[finding.severity.value] if finding.severity else "none",
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
                        "name": "hetzner-cloud-audit-skills",
                        "version": "0.5.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2)
