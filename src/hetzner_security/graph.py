"""Small typed attack graph; deliberately no graph database dependency."""

from __future__ import annotations

from collections import defaultdict, deque

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
