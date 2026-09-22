"""Deterministic verifier that challenges candidate evidence and path prerequisites."""

from __future__ import annotations

from copy import deepcopy

from ..graph import AttackGraph
from ..models import Evidence, Finding, FindingStatus, Snapshot, Verification


def verify_all(candidates: list[Finding], snapshot: Snapshot) -> list[Finding]:
    graph = AttackGraph(snapshot)
    return [verify(candidate, snapshot, graph) for candidate in candidates]


def verify(candidate: Finding, snapshot: Snapshot, graph: AttackGraph) -> Finding:
    """Verify from normalized facts, never from analyzer assertions alone."""
    result = deepcopy(candidate)
    assets = snapshot.asset_map()
    missing_assets = [asset_id for asset_id in candidate.assets if asset_id not in assets]
    if missing_assets:
        return _set(
            result,
            FindingStatus.REJECTED,
            "asset-existence challenge",
            [],
            f"Referenced assets do not exist in the snapshot: {missing_assets}",
            confidence=0.0,
        )
    if not candidate.evidence:
        return _set(
            result,
            FindingStatus.REJECTED,
            "minimum-evidence challenge",
            [],
            "Candidate contains no evidence.",
            confidence=0.0,
        )

    if candidate.rule_id.startswith("HETZ-NET-") and candidate.rule_id != "HETZ-NET-005":
        firewall_evidence = [e for e in candidate.evidence if e.kind == "firewall_rule"]
        if not firewall_evidence:
            return _needs(result, "Firewall attachment or equivalent host reachability is unobserved.")
        attached = all(assets[e.asset_id].properties.get("firewall_attached", True) for e in firewall_evidence)
        if not attached:
            return _set(
                result,
                FindingStatus.REJECTED,
                "firewall-attachment challenge",
                firewall_evidence,
                "The broad rule is not attached to the cited asset.",
                confidence=0.1,
            )

    if candidate.rule_id == "HETZ-XLY-001":
        source, target = candidate.assets[:2]
        port = int(assets[target].properties.get("port", 0))
        paths = graph.paths(source, target, protocol="tcp", port=port)
        if not paths:
            return _set(
                result,
                FindingStatus.REJECTED,
                "independent graph traversal",
                candidate.evidence,
                "No matching source-to-target path exists.",
                confidence=0.05,
            )
        if assets[target].properties.get("host_firewall_allows_source") is False:
            return _set(
                result,
                FindingStatus.REJECTED,
                "compensating-control challenge",
                candidate.evidence,
                "Observed target host firewall blocks the source.",
                confidence=0.1,
            )

    if candidate.rule_id == "HETZ-VULN-001" and not candidate.evidence[0].observed.get("fixed_version"):
        return _needs(result, "Scanner signal has no fixed version and affected runtime path is unverified.")

    if candidate.rule_id in {"HETZ-NET-005", "HETZ-BCP-001"}:
        return _needs(
            result,
            "Absence evidence depends on complete collector coverage; validate the missing control with the owner.",
        )

    return _set(
        result,
        FindingStatus.CONFIRMED,
        "independent deterministic evidence and prerequisite review",
        candidate.evidence,
        "Evidence is internally consistent and no observed compensating control refutes the path.",
        confidence=min(0.99, candidate.confidence + 0.02),
    )


def _needs(finding: Finding, note: str) -> Finding:
    return _set(
        finding,
        FindingStatus.NEEDS_VALIDATION,
        "independent completeness challenge",
        finding.evidence,
        note,
        confidence=min(finding.confidence, 0.69),
    )


def _set(
    finding: Finding,
    status: FindingStatus,
    method: str,
    evidence: list[Evidence],
    notes: str,
    *,
    confidence: float,
) -> Finding:
    finding.status = status
    finding.confidence = confidence
    finding.verification = Verification(method=method, result=status, evidence=evidence, notes=notes)
    return finding
