"""Evidence-first candidate rules spanning cloud, runtime, data, and declared intent."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from collections.abc import Callable
from dataclasses import replace

from ..flows import PortSet, port_set
from ..graph import AttackGraph
from ..host.parsers import pg_remote_decisions
from ..models import (
    Asset,
    Edge,
    Evidence,
    Finding,
    FindingStatus,
    Severity,
    Snapshot,
    Verification,
)
from ..provider_ranges import EDGE_RANGES
from ..providers import edge_provider, edge_ranges_as_of
from ..topology import classify_source

Rule = Callable[[Snapshot, AttackGraph], list[Finding]]
CGNAT_RANGE = ipaddress.IPv4Network("100.64.0.0/10")
PUBLIC_SOURCES = {"0.0.0.0/0", "::/0", "any", "internet"}
# Services that should never face the whole Internet: (protocol, first port, last port, name, severity).
# Rule IDs: SSH, PostgreSQL, and Redis keep their historical IDs; everything else is HETZ-NET-002.
SENSITIVE_SERVICES: tuple[tuple[str, int, int, str, Severity], ...] = (
    ("tcp", 21, 21, "FTP", Severity.HIGH),
    ("tcp", 23, 23, "Telnet", Severity.CRITICAL),
    ("tcp", 111, 111, "RPC portmapper", Severity.HIGH),
    ("udp", 111, 111, "RPC portmapper", Severity.HIGH),
    ("udp", 161, 161, "SNMP", Severity.HIGH),
    ("tcp", 445, 445, "SMB", Severity.CRITICAL),
    ("tcp", 2049, 2049, "NFS", Severity.HIGH),
    ("tcp", 2375, 2375, "Docker daemon", Severity.CRITICAL),
    ("tcp", 2376, 2376, "Docker daemon TLS", Severity.CRITICAL),
    ("tcp", 2379, 2380, "etcd", Severity.CRITICAL),
    ("tcp", 3306, 3306, "MySQL/MariaDB", Severity.HIGH),
    ("tcp", 3389, 3389, "RDP", Severity.HIGH),
    ("tcp", 5601, 5601, "Kibana", Severity.HIGH),
    ("tcp", 5672, 5672, "AMQP (RabbitMQ)", Severity.HIGH),
    ("tcp", 5984, 5984, "CouchDB", Severity.HIGH),
    ("tcp", 5985, 5986, "WinRM", Severity.HIGH),
    ("tcp", 6443, 6443, "Kubernetes API", Severity.CRITICAL),
    ("tcp", 8123, 8123, "ClickHouse HTTP", Severity.HIGH),
    ("tcp", 8200, 8200, "Vault API", Severity.HIGH),
    ("tcp", 8500, 8500, "Consul", Severity.CRITICAL),
    ("tcp", 9000, 9000, "Object storage / ClickHouse native", Severity.HIGH),
    ("tcp", 9090, 9090, "Prometheus", Severity.HIGH),
    ("tcp", 9092, 9092, "Kafka", Severity.HIGH),
    ("tcp", 9200, 9200, "Elasticsearch API", Severity.CRITICAL),
    ("tcp", 10250, 10250, "Kubelet API", Severity.CRITICAL),
    ("tcp", 11211, 11211, "Memcached", Severity.HIGH),
    ("udp", 11211, 11211, "Memcached (UDP amplification)", Severity.CRITICAL),
    ("tcp", 15672, 15672, "RabbitMQ management", Severity.HIGH),
    ("tcp", 27017, 27017, "MongoDB", Severity.CRITICAL),
    ("tcp", 30000, 32767, "Kubernetes NodePort range", Severity.HIGH),
)
MANAGEMENT_PORTS = {start: name for proto, start, end, name, _sev in SENSITIVE_SERVICES if proto == "tcp" and start == end}
WORLD_SOURCES = {"0.0.0.0/0", "::/0"}


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


def _public_ports(asset: Asset, protocol: str = "tcp") -> list[dict[str, object]]:
    rules = asset.properties.get("inbound", [])
    return [
        rule
        for rule in rules
        if set(rule.get("sources", [])) & PUBLIC_SOURCES and rule.get("protocol", "tcp") == protocol
    ]


def _all_ports(rule: dict[str, object]) -> bool:
    start, end = _port_bounds(rule)
    return start <= 1 and end >= 65535


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


def _port_bounds(rule: dict[str, object]) -> tuple[int, int]:
    start = _as_int(rule.get("port_from", rule.get("port", -1)))
    end = _as_int(rule.get("port_to", rule.get("port", start)), start)
    if rule.get("port") in {None, "any"} and start < 0:
        return 0, 65535
    return start, end


def public_service_exposure(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    output: list[Finding] = []
    services: list[tuple[str, int, int, str, str, Severity]] = [
        ("tcp", 22, 22, "HETZ-NET-001", "SSH reachable from the public internet", Severity.HIGH),
        ("tcp", 5432, 5432, "HETZ-NET-003", "PostgreSQL reachable from the public internet", Severity.HIGH),
        ("tcp", 6379, 6379, "HETZ-NET-004", "Redis reachable from the public internet", Severity.CRITICAL),
        *[
            (proto, first, last, "HETZ-NET-002", f"{name} reachable from the public internet", severity)
            for proto, first, last, name, severity in SENSITIVE_SERVICES
        ],
    ]
    for asset in snapshot.assets:
        if asset.type not in {"server", "firewall", "service"}:
            continue
        if asset.type == "firewall" and "applied_to" in asset.properties:
            continue  # evaluated as effective policy on the servers it is applied to, not as a loose rule set
        for proto in ("tcp", "udp"):
            for rule in _public_ports(asset, proto):
                if _all_ports(rule):
                    continue  # reported once as HETZ-FW-001 instead of once per service
                start, end = _port_bounds(rule)
                for service_proto, first, last, rule_id, title, severity in services:
                    if service_proto != proto or end < first or start > last:
                        continue
                    port = max(start, first)
                    label = f"{proto}/{first}" if first == last else f"{proto}/{first}-{last}"
                    evidence = [_evidence(asset, "firewall_rule", rule, "properties.inbound")]
                    suffix = "" if proto == "tcp" else "_udp"
                    listening = port_set(asset.properties.get(f"listening{suffix}_ports"))
                    host_allowed = port_set(asset.properties.get(f"host_firewall_allow{suffix}_ports"))
                    host_known = (
                        asset.properties.get("host_evidence")
                        and asset.properties.get(f"host_firewall_allow{suffix}_ports") is not None
                        and asset.properties.get(f"listening{suffix}_ports") is not None
                    )
                    if host_known:  # both layers observed; otherwise the finding stays needs_validation
                        # Flow intersection: cloud rule ∩ service range ∩ host firewall ∩ listener.
                        window = PortSet.of([(max(start, first), min(end, last))])
                        reachable = window.intersection(host_allowed).intersection(listening)
                        evidence.append(
                            _evidence(
                                asset,
                                "host_flow_intersection",
                                {"cloud": window.describe(), "host_firewall": host_allowed.intersection(window).describe() or "none",
                                 "listening": listening.intersection(window).describe() or "none", "reachable": reachable.describe() or "none"},
                                "properties.host_evidence",
                            )
                        )
                        if reachable:
                            port = next(iter(reachable))[0]
                    if port in listening:
                        evidence.append(
                            _evidence(asset, "listening_socket", {"protocol": proto, "port": port}, f"properties.listening{suffix}_ports")
                        )
                    if port in host_allowed:
                        evidence.append(
                            _evidence(asset, "host_firewall_allow", {"protocol": proto, "port": port}, f"properties.host_firewall_allow{suffix}_ports")
                        )
                    output.append(
                        _candidate(
                            rule_id,
                            title,
                            severity,
                            0.86,
                            [asset.id],
                            f"An inbound rule admits a public source to {label.upper()}.",
                            "Management and data services are reachable only from declared trusted sources.",
                            f"{label.upper()} admits {sorted(_string_set(rule.get('sources')) & PUBLIC_SOURCES)}.",
                            evidence,
                            ["internet", label, asset.id],
                            ["The rule is attached to the target and no downstream firewall blocks it."],
                            "An unauthenticated network peer can reach a sensitive service boundary.",
                            "Restrict the rule to a VPN, bastion, or explicit workload CIDR and verify host controls.",
                            ["https://docs.hetzner.com/cloud/firewalls/overview/"],
                            label if label != "tcp/" + str(port) else str(port),
                        )
                    )
    return output


def firewall_quality(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    """Firewall hygiene visible from the API alone: all-ports-open, unattached, IPv4/IPv6 drift, duplicates."""
    output: list[Finding] = []
    for firewall in (asset for asset in snapshot.assets if asset.type == "firewall"):
        inbound = firewall.properties.get("inbound", []) or []
        for rule in inbound:
            sources = _string_set(rule.get("sources"))
            if rule.get("protocol") in {"tcp", "udp"} and sources & WORLD_SOURCES and _all_ports(rule):
                output.append(
                    _candidate(
                        "HETZ-FW-001",
                        "Firewall rule opens every port to the whole Internet",
                        Severity.HIGH,
                        0.97,
                        [firewall.id],
                        f"{firewall.name} admits {str(rule.get('protocol')).upper()} on all ports from {sorted(sources & WORLD_SOURCES)}.",
                        "Inbound rules name the specific ports a service needs.",
                        "protocol any-port rule with a world source",
                        [_evidence(firewall, "firewall_rule", rule, "properties.inbound")],
                        ["internet", f"{rule.get('protocol')}/1-65535", firewall.id],
                        [],
                        "Every listener on every attached server is reachable from the Internet, including ones started later.",
                        "Replace the rule with explicit ports; keep admin access on a VPN or allow-list.",
                        ["https://docs.hetzner.com/cloud/firewalls/overview/"],
                        str(rule.get("protocol")),
                    )
                )
            if rule.get("protocol") in {"tcp", "udp"} and len(sources & WORLD_SOURCES) == 1:
                family = "IPv6 (::/0)" if "::/0" in sources else "IPv4 (0.0.0.0/0)"
                other = "IPv4" if "::/0" in sources else "IPv6"
                start, end = _port_bounds(rule)
                port = f"{start}" if start == end else f"{start}-{end}"
                output.append(
                    _candidate(
                        "HETZ-FW-003",
                        "Firewall rule treats IPv4 and IPv6 differently",
                        Severity.LOW,
                        0.9,
                        [firewall.id],
                        f"{firewall.name} opens {rule.get('protocol')}/{port} to {family} but not to {other}.",
                        "Public rules cover IPv4 and IPv6 consistently, or the difference is intentional and documented.",
                        f"only {family} is listed",
                        [_evidence(firewall, "firewall_rule", rule, "properties.inbound")],
                        [family, f"{rule.get('protocol')}/{port}", firewall.id],
                        [],
                        "A service may be reachable over one address family that reviews and scanners do not check.",
                        "Add the missing family to the rule, or record why only one family is exposed.",
                        ["https://docs.hetzner.com/cloud/firewalls/overview/"],
                        f"{rule.get('protocol')}/{port}",
                    )
                )
        seen: dict[str, int] = {}
        for rule in inbound:
            key = json.dumps([rule.get("protocol"), *_port_bounds(rule), sorted(_string_set(rule.get("sources")))])
            seen[key] = seen.get(key, 0) + 1
        duplicates = sum(count - 1 for count in seen.values() if count > 1)
        if duplicates:
            output.append(
                _candidate(
                    "HETZ-FW-004",
                    "Firewall contains duplicate rules",
                    Severity.LOW,
                    0.95,
                    [firewall.id],
                    f"{firewall.name} has {duplicates} duplicate inbound rule(s).",
                    "Each firewall rule is unique, so reviews and diffs stay readable.",
                    f"{duplicates} duplicate rule(s)",
                    [_evidence(firewall, "firewall_rules", len(inbound), "properties.inbound")],
                    [firewall.id],
                    [],
                    "Duplicates hide real changes in reviews and make drift harder to spot.",
                    "Remove the duplicate rules in IaC.",
                    ["https://docs.hetzner.com/cloud/firewalls/overview/"],
                )
            )
        applied = firewall.properties.get("applied_to")
        if isinstance(applied, list) and firewall.source == "hcloud_api":
            resources = [
                item for item in applied
                if item.get("type") == "server" or item.get("applied_to_resources")
            ]
            if not resources:
                output.append(
                    _candidate(
                        "HETZ-FW-002",
                        "Firewall is not applied to any resource",
                        Severity.LOW,
                        0.95,
                        [firewall.id],
                        f"{firewall.name} is attached to nothing" + (" (its label selector matches no server)" if applied else "") + ".",
                        "Every firewall protects something, or it is removed.",
                        "applied_to is empty",
                        [_evidence(firewall, "firewall_applied_to", applied, "properties.applied_to")],
                        [firewall.id],
                        [],
                        "An unused firewall suggests drift: the server it was meant for may be unprotected.",
                        "Check which server this firewall was meant for, then attach it or delete it through IaC.",
                        ["https://docs.hetzner.com/cloud/firewalls/overview/"],
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
        spec = str(expectation.get("port_spec", f"tcp/{port}"))
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
                f"{spec.upper()} sources equal the declared set {sorted(allowed)}.",
                f"Unexpected observed sources: {sorted(unexpected)}.",
                evidence,
                [*sorted(unexpected), spec, f"provider-policy:{target}"],
                ["Repository declaration is current and refers to the observed asset."],
                "The provider policy no longer enforces the reviewed source restriction; downstream reachability requires separate host and service evidence.",
                "Reconcile the runtime firewall to reviewed IaC, then import or remove manual drift.",
                ["https://developer.hashicorp.com/terraform/tutorials/state/resource-drift"],
                f"{spec}:{','.join(sorted(unexpected))}",
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
            declared = declared or any(
                e.get("kind") == "environment_policy"
                and e.get("target_environment") == target_env
                and source_env not in e.get("allowed_sources", [])
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
        entries = asset.properties.get("pg_hba", [])
        # First match wins: a reject line earlier in the file shadows a later trust line.
        for hba in pg_remote_decisions(entries):
            index = entries.index(hba)
            if hba.get("method") == "trust":
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
        if asset.type not in {"server", "postgres", "redis"} or asset.labels.get("environment") not in {"prod", "production"}:
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


def broad_private_data_path(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    """Find cloud-level paths to sensitive production servers from unrelated projects."""
    output: list[Finding] = []
    sensitive_tokens = {"db", "database", "postgres", "redis", "vault", "auth", "identity", "secrets"}
    servers = [asset for asset in snapshot.assets if asset.type == "server"]
    for target in servers:
        role = target.labels.get("role", "").lower()
        name = target.name.lower()
        explicit = target.labels.get("sensitivity", "").lower()
        if explicit in {"low", "none"}:
            continue
        if not (explicit == "high" or role in sensitive_tokens or any(token in name for token in sensitive_tokens)):
            continue
        target_project = target.labels.get("project") or target.labels.get("owner")
        candidate_paths: list[tuple[Asset, list[Edge]]] = []
        for source in servers:
            if source.id == target.id:
                continue
            source_project = source.labels.get("project") or source.labels.get("owner")
            if source_project and target_project and source_project == target_project:
                continue
            paths = graph.paths(source.id, target.id, protocol="tcp", max_depth=3)
            if paths:
                candidate_paths.append((source, paths[0]))
        if not candidate_paths:
            continue
        source, path = candidate_paths[0]
        evidence = [item for edge in path for item in edge.evidence]
        evidence.extend(
            [
                _evidence(source, "workload_identity", source.labels, "labels"),
                _evidence(target, "sensitive_role", {"role": role or target.name}, "labels.role"),
            ]
        )
        output.append(
            _candidate(
                "HETZ-XLY-002",
                "Unrelated workloads have a broad cloud path to a sensitive service host",
                Severity.HIGH,
                0.82,
                [source.id, target.id],
                f"{len(candidate_paths)} unrelated server(s) have a cloud-network path to {target.name}.",
                "Sensitive production hosts admit only explicitly required workload identities and ports.",
                "The servers share a private network. Hetzner Cloud Firewalls do not filter private network traffic, so every port is open at the cloud layer; only host firewalls and service authentication can restrict it.",
                evidence,
                [source.id, *[edge.target for edge in path]],
                ["A target service listens on the private interface.", "Host/runtime authentication does not block the source."],
                "Compromise of an unrelated workload can become lateral access to a database, identity, or secrets boundary.",
                "Move sensitive hosts to a dedicated private network, or enforce a host firewall (nftables or UFW) on the private interface that admits only required sources and ports; then verify application authentication.",
                ["https://docs.hetzner.com/cloud/firewalls/faq/", "https://docs.hetzner.com/cloud/networks/overview/"],
                target.id,
            )
        )
    return output


def deletion_protection_gap(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    affected = [
        asset
        for asset in snapshot.assets
        if asset.source == "hcloud_api"
        and asset.type in {"server", "volume", "network", "storage_box"}
        and (
            asset.type != "server"
            or asset.labels.get("environment") in {"prod", "production"}
            or bool(asset.properties.get("stateful"))
        )
        and (
            asset.properties.get("delete_protection") is False
            or asset.properties.get("protection", {}).get("delete") is False
        )
    ]
    if not affected:
        return []
    evidence = [
        _evidence(asset, "deletion_protection", False, "properties.protection.delete")
        for asset in affected
    ]
    return [
        _candidate(
            "HETZ-GOV-001",
            "Production or foundational assets lack deletion protection",
            Severity.MEDIUM,
            0.99,
            [asset.id for asset in affected],
            f"Deletion protection is disabled on {len(affected)} production or foundational asset(s).",
            "Stateful and foundational production resources resist accidental provider deletion.",
            "Provider configuration explicitly reports deletion protection disabled.",
            evidence,
            ["write-capable credential", "provider delete action", "production asset"],
            ["A write-capable credential or operator error."],
            "A mistaken or compromised provider action can remove production infrastructure more easily.",
            "Enable deletion protection through reviewed IaC for assets whose recovery requirements justify it.",
            ["https://docs.hetzner.com/cloud/servers/faq/#how-can-i-protect-my-server-from-deletion"],
        )
    ]


def label_governance(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    """Environment and role labels drive policy; unlabeled servers are silently outside it."""
    servers = [asset for asset in snapshot.assets if asset.type == "server" and asset.source == "hcloud_api"]
    missing = {
        asset.id: [key for key in ("environment", "role") if not asset.labels.get(key)]
        for asset in servers
    }
    affected = [asset for asset in servers if missing[asset.id]]
    if not affected:
        return []
    return [
        _candidate(
            "HETZ-GOV-004",
            "Policy cannot be evaluated for unlabeled servers",
            Severity.MEDIUM,
            0.98,
            [asset.id for asset in affected],
            f"{len(affected)} of {len(servers)} server(s) lack an environment or role label, so environment policy, "
            "cross-environment rules, and sensitive-host detection cannot be applied to them.",
            "Every server carries environment and role labels (plus owner, and optionally sensitivity=high).",
            "; ".join(f"{asset.name}: missing {', '.join(missing[asset.id])}" for asset in affected[:6])
            + (" …" if len(affected) > 6 else ""),
            [_evidence(asset, "resource_labels", asset.labels, "labels") for asset in affected],
            ["unlabeled server", "policy not evaluated", "undetected trust-boundary violation"],
            [],
            "Findings that depend on intent (staging reaching production, sensitive hosts on shared networks) are silently skipped for these servers.",
            "Add environment, role, and owner labels through IaC; mark databases and secrets hosts with sensitivity=high.",
            ["https://docs.hetzner.cloud/reference/cloud#labels"],
        )
    ]


def ownership_metadata_gap(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    affected = [
        asset
        for asset in snapshot.assets
        if asset.type == "server"
        and asset.source == "hcloud_api"
        and not asset.labels.get("owner")
        and not asset.labels.get("project")
    ]
    if not affected:
        return []
    return [
        _candidate(
            "HETZ-GOV-002",
            "Servers lack ownership metadata",
            Severity.LOW,
            0.99,
            [asset.id for asset in affected],
            f"{len(affected)} server(s) have neither an owner nor project label.",
            "Every long-lived server has an accountable owner or project identifier.",
            "Normalized provider labels contain neither key.",
            [_evidence(asset, "resource_labels", asset.labels, "labels") for asset in affected],
            ["unowned resource", "delayed security or lifecycle response"],
            [],
            "Unowned assets are harder to patch, review, expire, or include in incident response.",
            "Add owner, project, environment, role, and lifecycle labels through IaC.",
            ["https://docs.hetzner.cloud/reference/cloud#labels"],
        )
    ]


def _is_private_source(source: str) -> bool:
    try:
        network = ipaddress.ip_network(source, strict=False)
    except ValueError:
        return False
    if network.prefixlen == 0:
        return False
    if isinstance(network, ipaddress.IPv4Network) and network.subnet_of(CGNAT_RANGE):
        return True  # Tailscale and other carrier-grade NAT overlays
    return network.is_private


def edge_origin_bypass(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    """Flag web origins open to any address when peers restrict web ports to an edge proxy (CDN/WAF).

    The edge provider is recognized from its published, dated ranges (Cloudflare, Fastly, Bunny CDN,
    AWS CloudFront, Gcore, Imperva); the finding names the provider the peers use.
    """
    web_ports = {80, 443}

    def web_rules(asset: Asset) -> list[dict[str, object]]:
        output = []
        for rule in asset.properties.get("inbound", []) or []:
            start, end = _port_bounds(rule)
            if rule.get("protocol", "tcp") == "tcp" and any(start <= port <= end for port in web_ports):
                output.append(rule)
        return output

    def web_sources(asset: Asset) -> set[str]:
        return {
            classify_source(str(source), ())
            for rule in web_rules(asset)
            for source in rule.get("sources", []) or []  # type: ignore[attr-defined]
            if not _is_private_source(str(source))
        }

    def providers(asset: Asset) -> set[str]:
        return {
            name for rule in web_rules(asset) for source in rule.get("sources", []) or []  # type: ignore[attr-defined]
            if (name := edge_provider(str(source)))
        }

    servers = [asset for asset in snapshot.assets if asset.type == "server" and asset.properties.get("public_ip")]
    fronted = [asset for asset in servers if web_sources(asset) == {"edge"}]
    if not fronted:
        return []
    names = sorted({name for peer in fronted for name in providers(peer)})
    label = " / ".join(names) or "the edge proxy"
    output = []
    for asset in servers:
        if "world" not in web_sources(asset):
            continue
        rules = [
            rule
            for rule in asset.properties.get("inbound", []) or []
            if set(rule.get("sources", [])) & PUBLIC_SOURCES and rule.get("protocol", "tcp") == "tcp"
        ]
        output.append(
            _candidate(
                "HETZ-NET-006",
                f"Web origin is reachable directly, bypassing {label}",
                Severity.MEDIUM,
                0.8,
                [asset.id],
                f"{asset.name} accepts HTTP/HTTPS from any address, while {len(fronted)} other server(s) accept web traffic only from {label}.",
                f"Origins behind {label} accept web traffic only from its published ranges, or use a tunnel with no inbound port.",
                "tcp/80 or tcp/443 is open to 0.0.0.0/0 or ::/0.",
                [_evidence(asset, "firewall_rule", rule, "properties.inbound") for rule in rules]
                + [_evidence(peer, "edge_only_peer", sorted(providers(peer)), "properties.inbound") for peer in fronted[:3]]
                + [_evidence(asset, "edge_ranges_as_of", {name: edge_ranges_as_of(name) for name in names}, "provider_ranges.EDGE_RANGES")],
                ["internet", asset.id],
                [f"The origin is meant to be served through {label}."],
                f"Direct origin access bypasses {label}: its WAF, rate limiting, and DDoS protection, and it can reveal the origin IP.",
                f"Restrict tcp/80 and tcp/443 to {label} ranges, or publish through a tunnel (Cloudflare Tunnel, Tailscale Funnel, ngrok) "
                "and close the ports, if direct access is not intended.",
                sorted({str(entry["source"]) for entry in EDGE_RANGES.values() if entry["name"] in names}),
            )
        )
    return output


def deprecated_server_type(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    affected = [
        asset
        for asset in snapshot.assets
        if asset.type == "server"
        and isinstance(asset.properties.get("server_type"), dict)
        and asset.properties["server_type"].get("deprecated") is True
    ]
    if not affected:
        return []
    types = sorted({str(asset.properties["server_type"].get("name")) for asset in affected})
    return [
        _candidate(
            "HETZ-GOV-003",
            "Servers run a deprecated server type",
            Severity.LOW,
            0.99,
            [asset.id for asset in affected],
            f"{len(affected)} server(s) use deprecated type(s): {', '.join(types)}.",
            "Long-lived servers run a server type that Hetzner still offers.",
            "Provider catalog marks the server type as deprecated.",
            [
                _evidence(
                    asset,
                    "server_type_deprecation",
                    asset.properties["server_type"].get("deprecation"),
                    "properties.server_type.deprecation",
                )
                for asset in affected
            ],
            ["deprecated server type", "no like-for-like rebuild or scale-out", "delayed recovery"],
            [],
            "A rebuild, recreate, or disaster recovery cannot reuse the same type and may be delayed by an unplanned migration.",
            "Plan a reviewed migration to a current type, preferably through IaC, and record the rollback.",
            ["https://docs.hetzner.com/cloud/servers/overview/"],
        )
    ]


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
    firewall_quality,
    edge_origin_bypass,
    expectation_drift,
    cross_environment_data_path,
    broad_private_data_path,
    docker_runtime_risks,
    postgres_configuration,
    redis_configuration,
    backup_and_protection,
    deletion_protection_gap,
    ownership_metadata_gap,
    label_governance,
    deprecated_server_type,
    contextualize_vulnerabilities,
)


def hunt(snapshot: Snapshot) -> list[Finding]:
    from .attestations import ATTESTATION_RULES  # these modules build on helpers in this one
    from .changes import CHANGE_RULES
    from .host import HOST_RULES
    from .iac import IAC_RULES
    from .k8s import K8S_RULES
    from .objectstorage import OBJECT_STORAGE_RULES
    from .projects import PROJECT_RULES
    from .resources import RESOURCE_RULES
    from .robot import ROBOT_RULES

    graph = AttackGraph(snapshot)
    rules = (*RULES, *RESOURCE_RULES, *HOST_RULES, *CHANGE_RULES, *IAC_RULES, *PROJECT_RULES, *ROBOT_RULES, *OBJECT_STORAGE_RULES, *K8S_RULES, *ATTESTATION_RULES)
    candidates = [finding for rule in rules for finding in rule(snapshot, graph)]
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
