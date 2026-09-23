"""Owner-controlled suppression through Hetzner labels.

`audit.ignore=true` silences every finding on a resource; `audit.ignore.<RULE-ID>=true`
(for example `audit.ignore.HETZ-BCP-001=true`) silences one rule. A finding is suppressed only
when every asset it names opted out. Suppressions are always reported, never silent.
"""

from __future__ import annotations

from typing import Any

from ..models import Finding, Snapshot


def _ignores(labels: dict[str, str], rule_id: str) -> bool:
    truthy = {"true", "yes", "1"}
    return str(labels.get("audit.ignore", "")).lower() in truthy or str(labels.get(f"audit.ignore.{rule_id}", "")).lower() in truthy


def apply_suppressions(findings: list[Finding], snapshot: Snapshot) -> tuple[list[Finding], list[dict[str, Any]]]:
    labels = {asset.id: asset.labels for asset in snapshot.assets}
    kept: list[Finding] = []
    suppressed: list[dict[str, Any]] = []
    for finding in findings:
        if finding.assets and all(_ignores(labels.get(asset, {}), finding.rule_id) for asset in finding.assets):
            suppressed.append({"id": finding.id, "rule_id": finding.rule_id, "title": finding.title, "assets": finding.assets})
        else:
            kept.append(finding)
    return kept, suppressed
