"""Deterministic verifier that challenges candidate evidence and path prerequisites."""

from __future__ import annotations

from copy import deepcopy

from ..flows import port_set
from ..graph import AttackGraph
from ..models import Evidence, Finding, FindingStatus, Snapshot, Verification


def verify_all(candidates: list[Finding], snapshot: Snapshot) -> list[Finding]:
    graph = AttackGraph(snapshot)
    return [verify(candidate, snapshot, graph) for candidate in candidates]


def verify(candidate: Finding, snapshot: Snapshot, graph: AttackGraph) -> Finding:
    """Check a candidate's deterministic evidence contract.

    This is component separation, not an independent human or agent review.
    """
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

    if candidate.rule_id == "HETZ-DNS-001":
        return _needs(
            result,
            "The address may live at another provider or in another project; confirm before calling it dangling.",
        )
    if candidate.rule_id in {"HETZ-OBJ-001", "HETZ-OBJ-002"}:
        anonymous = assets[candidate.assets[0]].properties.get("anonymous_list")
        if anonymous is False and candidate.rule_id == "HETZ-OBJ-002":
            return _needs(result, "The policy names a wildcard principal, but an anonymous listing was refused; check which objects it covers.")
    if candidate.rule_id == "HETZ-K8S-002" and assets[candidate.assets[0]].properties.get("system"):
        return _needs(result, "System namespaces (CNI, CSI, monitoring) often need node access; confirm this one does.")
    if candidate.rule_id in {"HETZ-ROB-001", "HETZ-ROB-002"}:
        return _needs(result, "The Robot firewall admits the traffic; a host firewall and listener evidence decide reachability.")
    if candidate.rule_id in {"HETZ-IAC-001", "HETZ-IAC-004"} and (snapshot.metadata.get("terraform") or {}).get("kind") == "state":
        return _needs(result, "The state file may be older than the runtime; confirm with `terraform plan -refresh-only` or a saved plan.")
    if candidate.rule_id in {"HETZ-IAC-002", "HETZ-IAC-003"}:
        return _needs(result, "Terraform may manage these resources from another workspace or state file; confirm scope.")
    if candidate.rule_id.startswith("HETZ-ATT-"):
        answer = candidate.evidence[0].observed.get("answer") if isinstance(candidate.evidence[0].observed, dict) else None
        if answer is not False:
            return _needs(result, "The owner has not verified this control yet.")
        return _set(result, FindingStatus.CONFIRMED, "owner attestation", candidate.evidence,
                    "The owner stated that the control is not in place.", confidence=0.9)
    if candidate.rule_id.startswith("HETZ-CHG-"):
        return _needs(result, "Action history shows the change happened; confirm with the owner that it was intended.")
    if candidate.rule_id == "HETZ-LB-006":
        return _needs(result, "Direct backend access may be intended; confirm with the owner and check the host firewall.")
    if candidate.rule_id == "HETZ-IMG-001":
        return _needs(
            result,
            "The API reports the creation image; the running release may have been upgraded in place.",
        )

    if candidate.rule_id == "HETZ-NET-006":
        return _needs(
            result,
            "Peers that accept web traffic only from an edge proxy suggest the origin should not be public; confirm with the owner whether direct access is intended.",
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
        intersection = next((e.observed for e in candidate.evidence if e.kind == "host_flow_intersection"), None)
        if isinstance(intersection, dict) and intersection.get("reachable") == "none":
            return _set(
                result,
                FindingStatus.REJECTED,
                "host flow intersection",
                candidate.evidence,
                "The Cloud Firewall admits the port, but host evidence shows no port that is both admitted by the host "
                f"firewall ({intersection.get('host_firewall')}) and listening ({intersection.get('listening')}).",
                confidence=0.1,
            )
        port = _candidate_port(candidate)
        downstream_evidence = [
            evidence
            for evidence in candidate.evidence
            if evidence.kind in {"listening_socket", "host_firewall_allow"}
        ]
        if port is None or len(downstream_evidence) < 2:
            return _needs(
                result,
                "The provider rule is attached, but listener and host-firewall evidence are incomplete; validate end-to-end reachability safely.",
            )

    if candidate.rule_id == "HETZ-XLY-001":
        source, target = candidate.assets[:2]
        port = int(assets[target].properties.get("port", 0))
        paths = graph.paths(source, target, protocol="tcp", port=port)
        if not paths:
            return _set(
                result,
                FindingStatus.REJECTED,
                "deterministic graph traversal",
                candidate.evidence,
                "No matching source-to-target path exists.",
                confidence=0.05,
            )

    if candidate.rule_id == "HETZ-XLY-002":
        source, target = candidate.assets[:2]
        paths = graph.paths(source, target, protocol="tcp", max_depth=3)
        if not paths:
            return _set(
                result,
                FindingStatus.REJECTED,
                "deterministic graph traversal",
                candidate.evidence,
                "The cited cloud-level path no longer exists in the snapshot.",
                confidence=0.05,
            )
        target_properties = assets[target].properties
        # Private-network paths use the private view of the host when a bundle provides it.
        listening = port_set(target_properties.get("private_listening_ports", target_properties.get("listening_ports")))
        host_allowed = port_set(
            target_properties.get("host_firewall_private_allow_ports", target_properties.get("host_firewall_allow_ports"))
        )
        if not listening or not host_allowed:
            return _needs(
                result,
                "The cloud path is observed, but host firewall, listener/container publication, and application authorization remain decisive.",
            )
        if not listening.intersection(host_allowed) and target_properties.get("host_firewall_private_partial"):
            return _needs(
                result,
                "The host firewall admits only some sources inside the private network; whether this peer is one of them needs checking.",
            )
        if not listening.intersection(host_allowed):
            # Both layers are evidenced, but no port is both open in the host firewall and listening.
            return _set(
                result,
                FindingStatus.REJECTED,
                "listener and host-firewall intersection",
                candidate.evidence,
                f"No listening port ({listening.describe()}) is admitted by the host firewall ({host_allowed.describe()}).",
                confidence=0.1,
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

    if candidate.rule_id == "HETZ-DKR-005" and any(e.kind == "docker_user_chain" for e in candidate.evidence):
        return _needs(result, "DOCKER-USER rules exist and may already restrict the published ports; review them.")

    if candidate.rule_id in {"HETZ-PG-001", "HETZ-PG-003"}:
        target = candidate.assets[0]
        if not any(
            graph.reachable(source, target, protocol="tcp", port=5432)
            for source in ["internet", *assets]
            if source != target
        ):
            return _needs(
                result,
                "The HBA rule is unsafe if selected, but no source-to-PostgreSQL network path is evidenced.",
            )

    if candidate.rule_id == "HETZ-RDS-001":
        target = candidate.assets[0]
        if not any(
            graph.reachable(source, target, protocol="tcp", port=6379)
            for source in ["internet", *assets]
            if source != target
        ):
            return _needs(
                result,
                "The Redis configuration is unsafe if reachable, but no source-to-Redis network path is evidenced.",
            )

    if candidate.rule_id == "HETZ-VULN-001":
        signal = candidate.evidence[0].observed
        if not isinstance(signal, dict):
            return _needs(result, "Scanner output is not a structured vulnerability signal.")
        if signal.get("runtime_present") is False or signal.get("affected_code_path") is False:
            return _set(
                result,
                FindingStatus.REJECTED,
                "deterministic runtime-applicability challenge",
                candidate.evidence,
                "Runtime evidence refutes applicability of the scanner signal.",
                confidence=0.05,
            )
        missing = [
            field
            for field in ("runtime_present", "affected_code_path")
            if signal.get(field) is not True
        ]
        if missing:
            return _needs(
                result,
                "Scanner signal is not enough to confirm runtime applicability; safely verify: "
                + ", ".join(missing)
                + ".",
            )
        if not signal.get("fixed_version"):
            return _needs(result, "Runtime applicability is evidenced, but no fixed version is identified.")

    if candidate.rule_id in {"HETZ-NET-005", "HETZ-BCP-001"}:
        return _needs(
            result,
            "Absence evidence depends on complete collector coverage; validate the missing control with the owner.",
        )

    return _set(
        result,
        FindingStatus.CONFIRMED,
        "deterministic evidence-contract verification",
        candidate.evidence,
        "Evidence is internally consistent and no observed compensating control refutes the path.",
        confidence=min(0.99, candidate.confidence + 0.02),
    )


def _needs(finding: Finding, note: str) -> Finding:
    return _set(
        finding,
        FindingStatus.NEEDS_VALIDATION,
        "deterministic completeness challenge",
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
    if status != FindingStatus.CONFIRMED:
        if finding.severity is not None:
            # Severity is confirmed impact, so hypotheses carry none; the rule's proposal is kept as
            # potential_severity so filters and views can rank "possibly critical, one proof missing".
            finding.metadata["potential_severity"] = finding.severity.value
        finding.severity = None
    finding.verification = Verification(method=method, result=status, evidence=evidence, notes=notes)
    return finding


def _candidate_port(candidate: Finding) -> int | None:
    for evidence in candidate.evidence:
        if evidence.kind != "firewall_rule" or not isinstance(evidence.observed, dict):
            continue
        raw = evidence.observed.get("port", evidence.observed.get("port_from"))
        if isinstance(raw, int):
            return raw
        if isinstance(raw, str) and raw.isdigit():
            return int(raw)
    for item in candidate.attack_path:
        if item.startswith("tcp/") and item.removeprefix("tcp/").isdigit():
            return int(item.removeprefix("tcp/"))
    return None
