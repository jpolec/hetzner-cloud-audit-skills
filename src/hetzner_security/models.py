"""Stable data contracts shared by collectors, rules, verifiers, and reporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    CONFIRMED = "confirmed"
    NEEDS_VALIDATION = "needs_validation"
    REJECTED = "rejected"


@dataclass(frozen=True)
class Evidence:
    source: str
    kind: str
    asset_id: str
    observed: Any
    path: str | None = None
    collected_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Asset:
    id: str
    type: str
    name: str
    properties: dict[str, Any] = field(default_factory=dict)
    labels: dict[str, str] = field(default_factory=dict)
    source: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    relation: str
    protocol: str | None = None
    port: int | None = None
    evidence: tuple[Evidence, ...] = ()


@dataclass
class Verification:
    method: str
    result: FindingStatus
    evidence: list[Evidence]
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["result"] = self.result.value
        return data


@dataclass
class Finding:
    id: str
    rule_id: str
    title: str
    severity: Severity | None
    confidence: float
    status: FindingStatus
    assets: list[str]
    observation: str
    expected_state: str
    actual_state: str
    evidence: list[Evidence]
    attack_path: list[str]
    prerequisites: list[str]
    impact: str
    verification: Verification
    remediation: str
    references: list[str]
    discovered_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value if self.severity is not None else None
        data["status"] = self.status.value
        data["verification"]["result"] = self.verification.result.value
        return data


@dataclass
class Snapshot:
    assets: list[Asset] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    expectations: list[dict[str, Any]] = field(default_factory=list)
    signals: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def asset_map(self) -> dict[str, Asset]:
        return {asset.id: asset for asset in self.assets}
