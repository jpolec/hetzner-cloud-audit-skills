"""Small typed attack graph; deliberately no graph database dependency."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from .flows import port_set
from .models import Asset, Edge, Snapshot
from .text import md

# A public IP alone admits no traffic, and "runs" (server -> container/database) records ownership,
# not a network flow; neither is a hop an attacker can take by itself.
NON_TRAVERSABLE = {"public_interface", "runs"}


# Edge semantics, so a path says how each hop is taken:
#   FILTER  - a firewall admits traffic from a source (Internet -> server or LB)
#   FORWARD - a load balancer or node port forwards traffic to a backend
#   ROUTE   - a network delivers traffic to a member (private networks are unfiltered by Cloud Firewalls)
#   PIVOT   - the attacker must first compromise this hop's source and start a new flow from it
#   RUNTIME - a listener or published container port on the target
TRANSITION_PIVOT = "PIVOT"


def transition_kind(edge: Edge, assets: dict[str, Asset]) -> str:
    source = assets.get(edge.source)
    source_type = source.type if source else ("internet" if edge.source == "internet" else "")
    if edge.relation == "attached_to":
        return TRANSITION_PIVOT
    if edge.relation == "publishes":
        return "FORWARD" if source_type == "server" and edge.target.startswith("k8s:") else "RUNTIME"
    if edge.relation in {"contains"} or source_type in {"network", "vswitch"}:
        return "ROUTE"
    if source_type in {"load_balancer"}:
        return "FORWARD"
    if edge.source == "internet":
        return "FILTER"
    return "ROUTE"


class AttackGraph:
    def __init__(self, snapshot: Snapshot) -> None:
        self.assets: dict[str, Asset] = snapshot.asset_map()
        self.outgoing: dict[str, list[Edge]] = defaultdict(list)
        for edge in snapshot.edges:
            self.outgoing[edge.source].append(edge)

    def paths(
        self,
        source: str,
        target: str,
        *,
        protocol: str | None = None,
        port: int | None = None,
        max_depth: int = 6,
        max_paths: int = 50,
    ) -> list[list[Edge]]:
        """Return bounded simple paths matching service constraints on the final edge.

        Stops after ``max_paths`` matches so dense networks cannot blow up memory or runtime.
        """
        found: list[list[Edge]] = []
        queue: deque[tuple[str, list[Edge], frozenset[str]]] = deque(
            [(source, [], frozenset({source}))]
        )
        while queue:
            node, path, visited = queue.popleft()
            if len(path) >= max_depth:
                continue
            for edge in self.outgoing.get(node, []):
                if edge.target in visited:
                    continue
                if edge.relation in NON_TRAVERSABLE:
                    continue
                next_path = [*path, edge]
                if edge.target == target:
                    if port is not None and edge.relation not in {"allows", "publishes", "listens"}:
                        continue
                    if port is not None and not _edge_allows_port(edge, port):
                        continue
                    if protocol and edge.protocol not in (None, protocol):
                        continue
                    if port and edge.port not in (None, port):
                        continue
                    found.append(next_path)
                    if len(found) >= max_paths:
                        return found
                    continue
                queue.append((edge.target, next_path, visited | {edge.target}))
        return found

    def reachable(
        self,
        source: str,
        target: str,
        *,
        protocol: str | None = None,
        port: int | None = None,
        max_depth: int = 6,
    ) -> bool:
        return bool(
            self.paths(
                source,
                target,
                protocol=protocol,
                port=port,
                max_depth=max_depth,
            )
        )

    def resolve(self, value: str) -> str:
        if value in self.assets or value == "internet":
            return value
        matches = [asset.id for asset in self.assets.values() if asset.name == value]
        if not matches:
            raise ValueError(f"asset not found: {value}")
        if len(matches) > 1:
            raise ValueError(f"asset name is ambiguous: {value}; use a normalized asset ID")
        return matches[0]

    def explain_path(
        self,
        source: str,
        target: str,
        *,
        protocol: str | None = None,
        port: int | None = None,
        max_depth: int = 6,
    ) -> dict[str, Any]:
        resolved_source = self.resolve(source)
        resolved_target = self.resolve(target)
        paths = self.paths(
            resolved_source,
            resolved_target,
            protocol=protocol,
            port=port,
            max_depth=max_depth,
        )
        if not paths:
            return {
                "result": "unknown",
                "confidence": 0.0,
                "source": resolved_source,
                "target": resolved_target,
                "protocol": protocol,
                "port": port,
                "path": [],
                "evidence": [],
                "missing_evidence": [
                    "No matching allowed path is present in the collected graph; an unobserved host or runtime control may still exist."
                ],
            }
        path = min(paths, key=len)
        evidence = [item.to_dict() for edge in path for item in edge.evidence]
        target_asset = self.assets.get(resolved_target)
        target_type = target_asset.type if target_asset is not None else None
        target_properties = target_asset.properties if target_asset is not None else {}
        evidence_kinds = {item["kind"] for item in evidence}
        runtime_complete = bool(
            target_properties.get("host_firewall_allows_source") is True
            and (
                target_properties.get("listen_addresses")
                or target_properties.get("bind")
                or target_properties.get("listening_ports")
            )
        )
        if runtime_complete and target_asset is not None:
            evidence.extend(
                [
                    {
                        "source": target_asset.source,
                        "kind": "host_firewall_allow",
                        "asset_id": target_asset.id,
                        "observed": target_properties.get("host_firewall_allows_source"),
                        "path": "properties.host_firewall_allows_source",
                        "collected_at": None,
                    },
                    {
                        "source": target_asset.source,
                        "kind": "service_bind",
                        "asset_id": target_asset.id,
                        "observed": target_properties.get("listen_addresses")
                        or target_properties.get("bind")
                        or target_properties.get("listening_ports"),
                        "path": "properties",
                        "collected_at": None,
                    },
                ]
            )
            application_policy = target_properties.get("pg_hba") or target_properties.get("acl_enabled")
            if application_policy is not None:
                evidence.append(
                    {
                        "source": target_asset.source,
                        "kind": "application_policy",
                        "asset_id": target_asset.id,
                        "observed": application_policy,
                        "path": "properties",
                        "collected_at": None,
                    }
                )
        host_complete = bool(
            target_type == "server"
            and target_properties.get("host_evidence")
            and port is not None
            and port in port_set(target_properties.get("listening_ports"))
            and port in port_set(target_properties.get("host_firewall_allow_ports"))
        )
        complete = host_complete or target_type in {"postgres", "redis", "service", "container"} and (
            {"listening_socket", "host_firewall_allow"} <= evidence_kinds
            or runtime_complete
        )
        missing = [] if complete else [
            "Host firewall decision is not observed.",
            "Listener/container publication is not observed.",
            "Application authentication policy is not observed.",
        ]
        transitions = [
            {"from": edge.source, "to": edge.target, "kind": transition_kind(edge, self.assets), "port": edge.port}
            for edge in path
        ]
        pivots = sum(1 for item in transitions if item["kind"] == TRANSITION_PIVOT)
        host_known = bool(target_properties.get("host_evidence")) or runtime_complete
        return {
            "transitions": transitions,
            "reachability": {
                "cloud_path": True,
                "direct": pivots == 0,
                "pivots_required": pivots,
                "host_layer": "reachable" if complete else ("refuted or unknown" if host_known else "not observed"),
            },
            "result": "reachable" if complete else "cloud_path_present",
            "confidence": 0.97 if complete else 0.72,
            "source": resolved_source,
            "target": resolved_target,
            "protocol": protocol,
            "port": port,
            "path": [resolved_source, *[edge.target for edge in path]],
            "edges": [edge.to_dict() for edge in path],
            "evidence": evidence,
            "missing_evidence": missing,
        }


def render_path_markdown(result: dict[str, Any], names: dict[str, str] | None = None) -> str:
    lookup = names or {}

    def label(value: str) -> str:
        return md(lookup.get(value, value))

    lines = [
        "# Hetzner Attack Path",
        "",
        " → ".join(f"`{label(item)}`" for item in result["path"]) if result["path"] else "No allowed path observed.",
        "",
        f"**Result:** `{result['result'].upper()}`",
        "",
        f"**Confidence:** {result['confidence']:.2f}",
        "",
    ]
    reach = result.get("reachability")
    if reach:
        lines.extend([
            "| Layer | Answer |", "|---|---|",
            "| Cloud path | yes |",
            f"| Direct (no compromised hop) | {'yes' if reach['direct'] else 'no'} |",
            f"| Hops the attacker must compromise first | {reach['pivots_required']} |",
            f"| Host layer (firewall, listener) | {reach['host_layer']} |",
            "",
            "Hops: " + " → ".join(f"{label(item['to'])} ({item['kind']}{'/' + str(item['port']) if item.get('port') else ''})"
                                  for item in result.get("transitions", [])),
            "",
        ])
    if result["missing_evidence"]:
        lines.extend(["## Missing evidence", "", *[f"- {item}" for item in result["missing_evidence"]]])
    if result.get("evidence"):
        lines.extend(["", "## Evidence", ""])
        for item in result["evidence"]:
            lines.append(f"- `{md(item['kind'])}` · `{label(item['asset_id'])}` · `{item.get('path') or 'normalized graph'}`")
    return "\n".join(lines)


def _edge_allows_port(edge: Edge, port: int) -> bool:
    if edge.port is not None:
        return edge.port == port
    firewall_rules = [item.observed for item in edge.evidence if item.kind == "firewall_rule"]
    if not firewall_rules:
        return True
    for rule in firewall_rules:
        if not isinstance(rule, dict):
            continue
        start = rule.get("port_from")
        end = rule.get("port_to")
        if start is None and end is None:
            return True
        if isinstance(start, int) and isinstance(end, int) and start <= port <= end:
            return True
    return False
