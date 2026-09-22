"""Evidence-first candidate rules spanning cloud, runtime, data, and declared intent."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import replace

from ..graph import AttackGraph
from ..models import (
    Asset,
    Evidence,
    Finding,
    FindingStatus,
    Severity,
    Snapshot,
    Verification,
)

Rule = Callable[[Snapshot, AttackGraph], list[Finding]]
PUBLIC_SOURCES = {"0.0.0.0/0", "::/0", "any", "internet"}
MANAGEMENT_PORTS = {2375: "Docker daemon", 2376: "Docker daemon TLS", 6443: "Kubernetes API"}


def _fingerprint(rule_id: str, assets: list[str], discriminator: str = "") -> str:
    raw = json.dumps([rule_id, sorted(assets), discriminator], separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _evidence(asset: Asset, kind: str, observed: object, path: str | None = None) -> Evidence:
    return Evidence(asset.source, kind, asset.id, observed, path)


def _candidate(
    rule_id: str,
    title: str,
    severity: Severity,
    confidence: float,
    assets: list[str],
    observation: str,
    expected: str,
    actual: str,
    evidence: list[Evidence],
    attack_path: list[str],
    prerequisites: list[str],
    impact: str,
    remediation: str,
    references: list[str],
    discriminator: str = "",
) -> Finding:
    fid = f"{rule_id}-{_fingerprint(rule_id, assets, discriminator)}"
    return Finding(
        id=fid,
        rule_id=rule_id,
        title=title,
        severity=severity,
        confidence=confidence,
        status=FindingStatus.NEEDS_VALIDATION,
        assets=assets,
        observation=observation,
        expected_state=expected,
        actual_state=actual,
        evidence=evidence,
        attack_path=attack_path,
        prerequisites=prerequisites,
        impact=impact,
        verification=Verification(
            method="pending independent verification",
            result=FindingStatus.NEEDS_VALIDATION,
            evidence=[],
        ),
        remediation=remediation,
        references=references,
    )


def _public_ports(asset: Asset) -> list[dict[str, object]]:
    rules = asset.properties.get("inbound", [])
    return [
        rule
        for rule in rules
        if set(rule.get("sources", [])) & PUBLIC_SOURCES and rule.get("protocol", "tcp") == "tcp"
    ]


def _as_int(value: object, default: int = -1) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _string_set(value: object) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {item for item in value if isinstance(item, str)}


def _int_set(value: object) -> set[int]:
    if not isinstance(value, list):
        return set()
    return {_as_int(item) for item in value if _as_int(item) >= 0}


def public_service_exposure(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    output: list[Finding] = []
    services = {
        22: ("HETZ-NET-001", "SSH reachable from the public internet", Severity.HIGH),
        5432: ("HETZ-NET-003", "PostgreSQL reachable from the public internet", Severity.HIGH),
        6379: ("HETZ-NET-004", "Redis reachable from the public internet", Severity.CRITICAL),
        **{
            port: ("HETZ-NET-002", f"{name} reachable from the public internet", Severity.CRITICAL)
            for port, name in MANAGEMENT_PORTS.items()
        },
    }
    for asset in snapshot.assets:
        if asset.type not in {"server", "firewall", "service"}:
            continue
        for rule in _public_ports(asset):
            start = _as_int(rule.get("port", rule.get("port_from", -1)))
            end = _as_int(rule.get("port_to", start), start)
            for port, (rule_id, title, severity) in services.items():
                if not start <= port <= end:
                    continue
                evidence = [_evidence(asset, "firewall_rule", rule, "properties.inbound")]
                if port in _int_set(asset.properties.get("listening_ports")):
                    evidence.append(
                        _evidence(
                            asset,
                            "listening_socket",
                            {"protocol": "tcp", "port": port},
                            "properties.listening_ports",
                        )
                    )
                if port in _int_set(asset.properties.get("host_firewall_allow_ports")):
                    evidence.append(
                        _evidence(
                            asset,
                            "host_firewall_allow",
                            {"protocol": "tcp", "port": port},
                            "properties.host_firewall_allow_ports",
                        )
                    )
                output.append(
                    _candidate(
                        rule_id,
                        title,
                        severity,
                        0.86,
                        [asset.id],
                        f"An inbound rule admits a public source to TCP/{port}.",
                        "Management and data services are reachable only from declared trusted sources.",
                        f"TCP/{port} admits {sorted(_string_set(rule.get('sources')) & PUBLIC_SOURCES)}.",
                        evidence,
                        ["internet", f"tcp/{port}", asset.id],
                        ["The rule is attached to the target and no downstream firewall blocks it."],
                        "An unauthenticated network peer can reach a sensitive authentication boundary.",
                        "Restrict the rule to a VPN, bastion, or explicit workload CIDR and verify host controls.",
                        ["https://docs.hetzner.com/cloud/firewalls/overview/"],
                        str(port),
                    )
                )
    return output


def internet_host_without_firewall(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    protected = {edge.target for edges in graph.outgoing.values() for edge in edges if edge.relation == "protects"}
    output = []
    for asset in snapshot.assets:
        if asset.type != "server" or not asset.properties.get("public_ip"):
            continue
        if (
            asset.id in protected
            or asset.properties.get("firewall_attached") is True
            or asset.properties.get("host_firewall") is True
        ):
            continue
        output.append(
            _candidate(
                "HETZ-NET-005",
                "Internet-facing server has no observed firewall control",
                Severity.MEDIUM,
                0.72,
                [asset.id],
                "A public interface exists, but neither an attached Hetzner firewall nor an observed host firewall is present.",
                "Every public server has an independently evidenced ingress control.",
                "Public IP present; firewall attachment and host firewall evidence absent.",
                [_evidence(asset, "public_interface", asset.properties.get("public_ip"))],
                ["internet", asset.id],
                ["Collector coverage includes firewall attachments and host firewall state."],
                "Services that bind broadly may be reachable without a network policy boundary.",
                "Attach a least-privilege Hetzner firewall or provide verified host-firewall evidence.",
                ["https://docs.hetzner.com/cloud/firewalls/overview/"],
            )
        )
    return output


def expectation_drift(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    output: list[Finding] = []
    for expectation in snapshot.expectations:
        if expectation.get("kind") != "network_access":
            continue
        target = str(expectation.get("target"))
        port = int(expectation.get("port", 0))
        allowed = set(expectation.get("allowed_sources", []))
        observed = set(expectation.get("observed_sources", []))
        unexpected = observed - allowed
        if not unexpected:
            continue
        target_asset = snapshot.asset_map().get(target)
        observed_source = target_asset.source if target_asset is not None else "observed_state"
        evidence = [
            Evidence("repository", "declared_expectation", target, expectation.get("declared"), expectation.get("path")),
            Evidence(observed_source, "observed_access", target, sorted(observed)),
        ]
        output.append(
            _candidate(
                "HETZ-IAC-001",
                "Runtime network access diverges from declared infrastructure",
                Severity.MEDIUM,
                0.96,
                [target],
                "Declared and observed source ranges differ for a security-sensitive port.",
                f"TCP/{port} sources equal the declared set {sorted(allowed)}.",
                f"Unexpected observed sources: {sorted(unexpected)}.",
                evidence,
                [*sorted(unexpected), f"tcp/{port}", f"provider-policy:{target}"],
                ["Repository declaration is current and refers to the observed asset."],
                "The provider policy no longer enforces the reviewed source restriction; downstream reachability requires separate host and service evidence.",
                "Reconcile the runtime firewall to reviewed IaC, then import or remove manual drift.",
                ["https://developer.hashicorp.com/terraform/tutorials/state/resource-drift"],
                f"{port}:{','.join(sorted(unexpected))}",
            )
        )
    return output


def cross_environment_data_path(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    output: list[Finding] = []
    for source in snapshot.assets:
        source_env = source.labels.get("environment")
        if not source_env:
            continue
        for target in snapshot.assets:
            target_env = target.labels.get("environment")
            service = target.properties.get("service")
            port = int(target.properties.get("port", 0))
            if service not in {"postgres", "redis"} or not target_env or source_env == target_env:
                continue
            paths = graph.paths(source.id, target.id, protocol="tcp", port=port)
            if not paths:
                continue
            declared = any(
                e.get("kind") == "environment_isolation"
                and source_env in e.get("separate", [])
                and target_env in e.get("separate", [])
                for e in snapshot.expectations
            )
            if not declared:
                continue
            path = paths[0]
            ev = [item for edge in path for item in edge.evidence]
            ev.extend(
                [
                    _evidence(source, "environment_label", source_env, "labels.environment"),
                    _evidence(target, "environment_label", target_env, "labels.environment"),
                ]
            )
            output.append(
                _candidate(
                    "HETZ-XLY-001",
                    f"{source_env} workload can reach {target_env} {service}",
                    Severity.HIGH,
                    0.94,
                    [source.id, target.id],
                    "A cross-environment attack-graph path contradicts an explicit isolation declaration.",
                    f"{source_env} and {target_env} data planes are isolated.",
                    f"A TCP/{port} path exists: " + " -> ".join([source.id, *[e.target for e in path]]),
                    ev,
                    [source.id, *[edge.target for edge in path]],
                    [f"Compromise or malicious execution on {source.id}.", "Target service accepts the source identity."],
                    "Compromise of a lower-trust environment can become unauthorized database or cache access.",
                    "Separate environment networks and enforce target-side allowlists for the exact clients.",
                    ["https://docs.hetzner.com/cloud/networks/overview/"],
                    f"{source_env}:{target_env}:{service}",
                )
            )
    return output


def docker_runtime_risks(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    output: list[Finding] = []
    checks = [
        ("privileged", True, "HETZ-DKR-001", "Privileged container crosses the host isolation boundary", Severity.HIGH),
        ("docker_socket", True, "HETZ-DKR-002", "Container can control the Docker daemon", Severity.CRITICAL),
        ("host_pid", True, "HETZ-DKR-003", "Container shares the host PID namespace", Severity.HIGH),
        ("host_network", True, "HETZ-DKR-004", "Container shares the host network namespace", Severity.MEDIUM),
    ]
    for asset in snapshot.assets:
        if asset.type != "container":
            continue
        for field, unsafe, rule_id, title, severity in checks:
            if asset.properties.get(field) != unsafe:
                continue
            output.append(
                _candidate(
                    rule_id,
                    title,
                    severity,
                    0.95,
                    [asset.id],
                    f"Runtime inspection reports {field}=true.",
                    "The workload has only capabilities required by its declared function.",
                    f"{field}=true",
                    [_evidence(asset, "container_runtime", {field: True}, f"properties.{field}")],
                    [asset.id, "container_runtime", "host"],
                    ["Code execution in the container."],
                    "Container compromise can expand to host or sibling-workload control.",
                    f"Disable {field} and grant a narrower capability or mediated service.",
                    ["https://docs.docker.com/engine/security/"],
                )
            )
    return output


def postgres_configuration(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    output: list[Finding] = []
    for asset in snapshot.assets:
        if asset.type != "postgres":
            continue
        for index, hba in enumerate(asset.properties.get("pg_hba", [])):
            if hba.get("method") == "trust" and hba.get("address") in PUBLIC_SOURCES | {"0.0.0.0/0", "::/0"}:
                output.append(
                    _candidate(
                        "HETZ-PG-001",
                        "Broad PostgreSQL trust authentication bypasses credentials",
                        Severity.CRITICAL,
                        0.99,
                        [asset.id],
                        "pg_hba.conf trusts a broad network range.",
                        "Remote database connections use authenticated, encrypted methods scoped to required clients.",
                        f"HBA rule {index} uses trust for {hba.get('address')}.",
                        [_evidence(asset, "pg_hba_rule", hba, f"properties.pg_hba[{index}]")],
                        [str(hba.get("address")), asset.id, "postgres authentication"],
                        ["A network path reaches PostgreSQL and the HBA rule is selected."],
                        "A reachable client can select an allowed database role without presenting a password.",
                        "Replace trust with scram-sha-256 or certificate authentication and scope the CIDR.",
                        ["https://www.postgresql.org/docs/current/auth-pg-hba-conf.html"],
                    )
                )
        unexpected_superusers = [
            role.get("name")
            for role in asset.properties.get("roles", [])
            if role.get("superuser") and not role.get("expected_superuser")
        ]
        if unexpected_superusers:
            output.append(
                _candidate(
                    "HETZ-PG-002",
                    "Unexpected PostgreSQL roles hold superuser capability",
                    Severity.HIGH,
                    0.91,
                    [asset.id],
                    "Role inventory marks superuser roles outside the declared allowlist.",
                    "Only explicitly designated break-glass or administrative roles are superusers.",
                    f"Unexpected superusers: {unexpected_superusers}.",
                    [_evidence(asset, "postgres_roles", unexpected_superusers, "properties.roles")],
                    ["database credentials", *[str(r) for r in unexpected_superusers], asset.id],
                    ["Ability to authenticate as one of the listed roles."],
                    "The roles can bypass database authorization and alter security-sensitive configuration.",
                    "Revoke SUPERUSER and grant the minimum object and administrative privileges.",
                    ["https://www.postgresql.org/docs/current/role-attributes.html"],
                )
            )
    return output


def redis_configuration(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    output: list[Finding] = []
    for asset in snapshot.assets:
        if asset.type != "redis":
            continue
        props = asset.properties
        broad_bind = bool(set(props.get("bind", [])) & {"0.0.0.0", "::", "*"})
        no_auth = not props.get("requirepass") and not props.get("acl_enabled")
        if broad_bind and not props.get("protected_mode", True) and no_auth:
            output.append(
                _candidate(
                    "HETZ-RDS-001",
                    "Redis accepts non-local clients without an authentication control",
                    Severity.CRITICAL,
                    0.98,
                    [asset.id],
                    "Broad bind, disabled protected mode, and absent ACL/password evidence coincide.",
                    "Redis is limited to trusted clients and requires a scoped ACL identity.",
                    "bind is broad; protected-mode=no; no authentication configured.",
                    [_evidence(asset, "redis_config", {k: props.get(k) for k in ("bind", "protected_mode", "acl_enabled")})],
                    ["reachable network peer", asset.id, "redis command surface"],
                    ["A network path reaches the Redis listener."],
                    "A client can read, alter, or destroy cached or persistent data.",
                    "Bind to the required interface, enable protected mode, and configure least-privilege ACLs.",
                    ["https://redis.io/docs/latest/operate/oss_and_stack/management/security/"],
                )
            )
    return output


def backup_and_protection(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    output: list[Finding] = []
    for asset in snapshot.assets:
        if asset.type not in {"server", "postgres", "redis"} or asset.labels.get("environment") != "prod":
            continue
        if asset.properties.get("stateful") and not asset.properties.get("backup_enabled"):
            output.append(
                _candidate(
                    "HETZ-BCP-001",
                    "Production stateful asset lacks observed backup coverage",
                    Severity.MEDIUM,
                    0.75,
                    [asset.id],
                    "The asset is declared production and stateful, but no backup configuration is observed.",
                    "Production state has a tested, declared recovery mechanism.",
                    "backup_enabled=false or absent.",
                    [_evidence(asset, "backup_state", asset.properties.get("backup_enabled"), "properties.backup_enabled")],
                    [asset.id, "data loss", "unrecoverable state"],
                    ["Collector coverage includes the relevant backup mechanism."],
                    "Deletion, corruption, or compromise may cause unrecoverable service data loss.",
                    "Enable provider or application-consistent backups and record a restore test.",
                    ["https://docs.hetzner.com/cloud/servers/backups-snapshots/overview/"],
                )
            )
    return output


def contextualize_vulnerabilities(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    output: list[Finding] = []
    for signal in snapshot.signals:
        if signal.get("type") != "vulnerability" or signal.get("severity") not in {"HIGH", "CRITICAL", "high", "critical"}:
            continue
        asset_id = str(signal.get("asset_id"))
        reachable = graph.reachable("internet", asset_id)
        severity = Severity.HIGH if reachable else Severity.MEDIUM
        confidence = 0.82 if signal.get("fixed_version") else 0.68
        output.append(
            _candidate(
                "HETZ-VULN-001",
                f"Vulnerable component in {'internet-reachable' if reachable else 'non-public'} workload",
                severity,
                confidence,
                [asset_id],
                f"{signal.get('scanner')} reports {signal.get('vulnerability_id')} in {signal.get('package')}.",
                "Deployed components have no applicable high-impact known vulnerabilities.",
                f"Installed {signal.get('installed_version')}; fixed {signal.get('fixed_version', 'unknown')}; internet_reachable={reachable}.",
                [Evidence(str(signal.get("scanner", "external_scanner")), "vulnerability_signal", asset_id, signal)],
                ["internet", asset_id] if reachable else [asset_id, "local vulnerable component"],
                ["The vulnerable component and affected code path are present at runtime."],
                "Impact depends on exploit preconditions; reachability changes priority but not vulnerable status.",
                "Upgrade to the fixed version and verify whether the affected component is loaded or reachable.",
                [str(signal.get("primary_url", "https://nvd.nist.gov/"))],
                str(signal.get("vulnerability_id")),
            )
        )
    return output


RULES: tuple[Rule, ...] = (
    public_service_exposure,
    internet_host_without_firewall,
    expectation_drift,
    cross_environment_data_path,
    docker_runtime_risks,
    postgres_configuration,
    redis_configuration,
    backup_and_protection,
    contextualize_vulnerabilities,
)


def hunt(snapshot: Snapshot) -> list[Finding]:
    graph = AttackGraph(snapshot)
    candidates = [finding for rule in RULES for finding in rule(snapshot, graph)]
    collected_at = snapshot.metadata.get("collected_at")
    if isinstance(collected_at, str):
        for candidate in candidates:
            candidate.discovered_at = collected_at
            candidate.evidence = [
                evidence
                if evidence.collected_at is not None
                else replace(evidence, collected_at=collected_at)
                for evidence in candidate.evidence
            ]
    deduplicated = {finding.id: finding for finding in candidates}
    return sorted(deduplicated.values(), key=lambda finding: finding.id)
