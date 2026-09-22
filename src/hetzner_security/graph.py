"""Small typed attack graph; deliberately no graph database dependency."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from .models import Asset, Edge, Snapshot


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
    ) -> list[list[Edge]]:
        """Return bounded simple paths matching service constraints on the final edge."""
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
        complete = target_type in {"postgres", "redis", "service"} and (
            {"listening_socket", "host_firewall_allow"} <= evidence_kinds
            or runtime_complete
        )
        missing = [] if complete else [
            "Host firewall decision is not observed.",
            "Listener/container publication is not observed.",
            "Application authentication policy is not observed.",
        ]
        return {
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


def render_path_markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Hetzner Attack Path",
        "",
        " → ".join(f"`{item}`" for item in result["path"]) if result["path"] else "No allowed path observed.",
        "",
        f"**Result:** `{result['result'].upper()}`",
        "",
        f"**Confidence:** {result['confidence']:.2f}",
        "",
    ]
    if result["missing_evidence"]:
        lines.extend(["## Missing evidence", "", *[f"- {item}" for item in result["missing_evidence"]]])
    if result.get("evidence"):
        lines.extend(["", "## Evidence", ""])
        for item in result["evidence"]:
            lines.append(f"- `{item['kind']}` · `{item['asset_id']}` · `{item.get('path') or 'normalized graph'}`")
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
