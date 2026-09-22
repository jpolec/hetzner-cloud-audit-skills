"""Deterministic coverage ledger for additive, auditable runs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .models import Snapshot


@dataclass
class CoverageUnit:
    coverage_id: str
    asset_id: str
    layer: str
    attack_class: str
    status: str = "planned"
    evidence_sources: list[str] = field(default_factory=list)
    result_fingerprints: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)


def plan_coverage(snapshot: Snapshot) -> list[CoverageUnit]:
    units: list[CoverageUnit] = []
    classes = {
        "server": ("network-exposure", "backup-resilience"),
        "firewall": ("network-policy",),
        "container": ("runtime-isolation", "secret-exposure"),
        "postgres": ("authentication", "authorization", "transport", "recovery"),
        "redis": ("authentication", "transport", "command-surface", "recovery"),
        "network": ("segmentation", "lateral-movement"),
    }
    for asset in snapshot.assets:
        for attack_class in classes.get(asset.type, ("configuration",)):
            identity = f"{asset.id}\x00{asset.type}\x00{attack_class}"
            digest = hashlib.sha256(identity.encode()).hexdigest()[:20]
            units.append(CoverageUnit(f"coverage/{digest}", asset.id, asset.type, attack_class))
    return sorted(units, key=lambda unit: unit.coverage_id)


def update_coverage(units: list[CoverageUnit], findings: list[Any]) -> None:
    by_asset: dict[str, list[Any]] = {}
    for finding in findings:
        for asset_id in finding.assets:
            by_asset.setdefault(asset_id, []).append(finding)
    for unit in units:
        matches = by_asset.get(unit.asset_id, [])
        unit.status = "candidate" if matches else "covered"
        unit.result_fingerprints = sorted({finding.id for finding in matches})
        unit.evidence_sources = sorted(
            {e.source for finding in matches for e in finding.evidence}
        ) or ["normalized_snapshot"]


def save_coverage(path: Path, units: list[CoverageUnit], *, prior_path: Path | None = None) -> None:
    prior: dict[str, Any] = {}
    if prior_path and prior_path.exists():
        prior = {item["coverage_id"]: item for item in json.loads(prior_path.read_text())}
    payload = []
    for unit in units:
        item = asdict(unit)
        item["prior_status"] = prior.get(unit.coverage_id, {}).get("status")
        payload.append(item)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def render_coverage(units: list[CoverageUnit]) -> str:
    """Render a report-only ledger without requiring a filesystem write."""
    return json.dumps([{**asdict(unit), "prior_status": None} for unit in units], indent=2)
