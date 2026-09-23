"""Egress policy (`[roles.<role>] internet_egress` in the owner policy): can a server of this role
connect straight to the Internet?

The Cloud Firewall decides provider-level egress (no outbound rule = everything allowed). A host
firewall OUTPUT chain or a proxy may still block it, so findings stay needs_validation until host
evidence covers egress.
"""

from __future__ import annotations

from ..flows import PortSet, egress_flowspace
from ..graph import AttackGraph
from ..models import Finding, Severity, Snapshot
from .rules import _candidate, _evidence

SENSITIVE_ROLES = {"db", "database", "postgres", "redis", "replica", "vault", "auth", "identity", "secrets", "kms"}


def _allowed(value: object) -> dict[str, PortSet]:
    allowed: dict[str, PortSet] = {"tcp": PortSet(), "udp": PortSet()}
    if isinstance(value, list):
        for item in value:
            protocol, _, ports = str(item).partition("/")
            first, _, last = ports.partition("-")
            if protocol in allowed and first.isdigit():
                allowed[protocol] = allowed[protocol].union(PortSet.of([(int(first), int(last or first))]))
    return allowed


def egress_policy(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    output: list[Finding] = []
    for expectation in snapshot.expectations:
        if expectation.get("kind") != "role_egress":
            continue
        role = str(expectation.get("role", "")).lower()
        allowed = _allowed(expectation.get("internet_egress"))
        for server in snapshot.assets:
            if server.type != "server" or server.labels.get("role", "").lower() != role:
                continue
            space = egress_flowspace(server)
            excess: dict[str, PortSet] = {}
            for (_family, protocol), rects in space.items():
                ports = PortSet.of([(p1, p2) for _s1, _s2, p1, p2 in rects])
                extra = ports.difference(allowed.get(protocol, PortSet()))
                if extra:
                    excess[protocol] = excess.get(protocol, PortSet()).union(extra)
            if not excess:
                continue
            unrestricted = not server.properties.get("outbound") or not server.properties.get("firewall_attached")
            described = "; ".join(f"{protocol.upper()} {ports.describe()}" for protocol, ports in sorted(excess.items()))
            output.append(
                _candidate(
                    "HETZ-EGR-001",
                    f"{server.name} ({role}) can connect directly to the Internet",
                    Severity.HIGH if role in SENSITIVE_ROLES else Severity.MEDIUM,
                    0.85,
                    [server.id],
                    ("No Cloud Firewall outbound rule restricts egress, so every destination and port is allowed."
                     if unrestricted else "Cloud Firewall outbound rules allow more than the policy permits."),
                    f"Policy for role {role}: internet_egress = {expectation.get('internet_egress')!r}.",
                    f"Allowed beyond policy: {described}.",
                    [_evidence(server, "egress_rule", server.properties.get("outbound") or "no outbound rules (all egress allowed)", "properties.outbound")],
                    [server.id, "internet"],
                    ["Code execution on the server.", "No host firewall OUTPUT rule or proxy blocks the traffic."],
                    "A compromised server can send data to any host or reach attacker infrastructure (exfiltration, command and control).",
                    "Add outbound rules to its Cloud Firewall for the destinations it needs (updates, monitoring); every other egress is then denied.",
                    ["https://docs.hetzner.com/cloud/firewalls/overview/"],
                    role,
                )
            )
    return output


EGRESS_RULES = (egress_policy,)
