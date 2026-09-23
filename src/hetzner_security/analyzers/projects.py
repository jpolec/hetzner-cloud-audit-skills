"""Cross-project trust boundaries (merged snapshots): one project's firewall trusting another
project's public address, and environments mixed inside one project.
"""

from __future__ import annotations

import ipaddress
from collections import Counter

from ..graph import AttackGraph
from ..models import Finding, Severity, Snapshot
from ..projects import public_addresses
from .rules import _candidate, _evidence


def cross_project_trust(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    """HETZ-XPR-001: a firewall rule admits the public address of a server in another project."""
    owners: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str, str]] = []
    for asset in snapshot.assets:
        project = asset.properties.get("project")
        if project:
            for address in public_addresses(asset):
                try:
                    owners.append((ipaddress.ip_network(address, strict=False), str(project), asset.id))
                except ValueError:
                    continue
    if len({project for _, project, _ in owners}) < 2:
        return []
    output: list[Finding] = []
    for asset in snapshot.assets:
        project = asset.properties.get("project")
        if asset.type != "server" or not project:
            continue
        crossings = []
        for rule in asset.properties.get("inbound") or []:
            for source in rule.get("sources") or []:
                try:
                    network = ipaddress.ip_network(str(source), strict=False)
                except ValueError:
                    continue
                if network.prefixlen < (24 if network.version == 4 else 48):
                    continue  # wide ranges are not a deliberate trust in one host
                for owned, other_project, other_id in owners:
                    # IPv6 servers own a /64; a /128 rule inside it still names that server.
                    if other_project != project and owned.version == network.version and owned.overlaps(network):
                        crossings.append({"source": str(source), "port_from": rule.get("port_from"), "port_to": rule.get("port_to"),
                                          "peer": other_id, "peer_project": other_project})
        if not crossings:
            continue
        peers = sorted({item["peer_project"] for item in crossings})
        output.append(
            _candidate(
                "HETZ-XPR-001",
                f"Firewall trusts servers from another project ({', '.join(peers)})",
                Severity.MEDIUM if asset.labels.get("environment") in {"prod", "production"} else Severity.LOW,
                0.9,
                [asset.id, *sorted({item["peer"] for item in crossings})],
                f"{asset.name} in project {project} admits the public address of {len(crossings)} peer(s) in other projects.",
                "Cross-project traffic is explicit, encrypted, and limited; production does not trust less protected projects.",
                "; ".join(f"{item['source']} ({item['peer_project']}) → ports {item['port_from'] or 'all'}-{item['port_to'] or ''}".rstrip("-") for item in crossings[:5]),
                [_evidence(asset, "cross_project_rule", crossings, "properties.inbound")],
                [crossings[0]["peer"], "public Internet", asset.id],
                ["The peer project's server is compromised, or its address is reassigned."],
                "A compromise in the other project reaches this one over the public network, outside any private network.",
                "Encrypt the path (WireGuard/Tailscale or TLS with client auth), or move both into one project with a private network.",
                ["https://docs.hetzner.com/cloud/networks/faq/"],
                ",".join(peers),
            )
        )
    return output


def mixed_environments(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    """HETZ-XPR-002: a project holds more than one environment label, including production."""
    by_project: dict[str, Counter[str]] = {}
    members: dict[str, list[str]] = {}
    for asset in snapshot.assets:
        project, environment = asset.properties.get("project"), asset.labels.get("environment")
        if asset.type == "server" and project and environment:
            by_project.setdefault(str(project), Counter())[environment] += 1
            members.setdefault(str(project), []).append(asset.id)
    output: list[Finding] = []
    for project, environments in sorted(by_project.items()):
        if len(environments) < 2 or not set(environments) & {"prod", "production"}:
            continue
        output.append(
            _candidate(
                "HETZ-XPR-002",
                f"Project {project} mixes production with other environments",
                Severity.LOW,
                0.9,
                members[project],
                f"Server environment labels in {project}: {dict(environments)}.",
                "Production runs in its own project, so tokens, members, and private networks do not span environments.",
                f"{dict(environments)}",
                [_evidence(snapshot.asset_map()[members[project][0]], "environment_labels", dict(environments), "labels.environment")],
                ["project token or member", project],
                ["A token or console member of this project is compromised or misused."],
                "Any token or member of the project can change production; private networks join staging and production any-to-any.",
                "Move production to a dedicated project, or document why the environments share one.",
                ["https://docs.hetzner.com/cloud/general/projects/"],
                project,
            )
        )
    return output


PROJECT_RULES = (cross_project_trust, mixed_environments)
