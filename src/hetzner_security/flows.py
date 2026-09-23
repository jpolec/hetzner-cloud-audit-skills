"""Allowed-flow algebra: port sets and effective Internet exposure per asset.

An asset's exposure is a set of allowed flows keyed by (address family, protocol, source class),
each holding the set of destination ports. Comparing two snapshots then becomes set difference:
widening 80-443 to 80-8443 is a regression even when the rule keeps the same identity, and a new
public IP behind a deny-all firewall is not.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any

from .models import Asset, Edge, Snapshot

MAX_PORT = 65535
WORLD = {"ipv4": "0.0.0.0/0", "ipv6": "::/0"}
WIDE_PREFIX = {"ipv4": 8, "ipv6": 16}
# RFC 1918, CGNAT (Tailscale), loopback, link-local, and IPv6 ULA/link-local. Not ipaddress.is_private,
# which also treats documentation ranges as private.
INTERNAL = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
                  "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128")
)  # public CIDRs at least this wide count as "wide", not allow-list


@dataclass(frozen=True)
class PortSet:
    """A normalized, immutable set of ports stored as sorted, non-overlapping inclusive ranges."""

    ranges: tuple[tuple[int, int], ...] = ()

    @classmethod
    def of(cls, spans: Iterable[tuple[int, int]]) -> PortSet:
        cleaned = sorted((max(0, a), min(MAX_PORT, b)) for a, b in spans if a <= b)
        merged: list[tuple[int, int]] = []
        for start, end in cleaned:
            if merged and start <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        return cls(tuple(merged))

    @classmethod
    def full(cls) -> PortSet:
        return cls(((0, MAX_PORT),))

    def __bool__(self) -> bool:
        return bool(self.ranges)

    def __iter__(self) -> Iterator[tuple[int, int]]:
        return iter(self.ranges)

    def __contains__(self, port: object) -> bool:
        return isinstance(port, int) and any(a <= port <= b for a, b in self.ranges)

    def union(self, other: PortSet) -> PortSet:
        return PortSet.of([*self.ranges, *other.ranges])

    def intersection(self, other: PortSet) -> PortSet:
        output = []
        for a1, b1 in self.ranges:
            for a2, b2 in other.ranges:
                if max(a1, a2) <= min(b1, b2):
                    output.append((max(a1, a2), min(b1, b2)))
        return PortSet.of(output)

    def difference(self, other: PortSet) -> PortSet:
        output: list[tuple[int, int]] = []
        for start, end in self.ranges:
            pieces = [(start, end)]
            for cut_start, cut_end in other.ranges:
                next_pieces = []
                for a, b in pieces:
                    if cut_end < a or cut_start > b:
                        next_pieces.append((a, b))
                        continue
                    if a < cut_start:
                        next_pieces.append((a, cut_start - 1))
                    if cut_end < b:
                        next_pieces.append((cut_end + 1, b))
                pieces = next_pieces
            output.extend(pieces)
        return PortSet.of(output)

    def size(self) -> int:
        return sum(b - a + 1 for a, b in self.ranges)

    def describe(self) -> str:
        if self.ranges == ((0, MAX_PORT),) or self.ranges == ((1, MAX_PORT),):
            return "all"
        return ", ".join(str(a) if a == b else f"{a}-{b}" for a, b in self.ranges)


def port_set(value: object) -> PortSet:
    """Read ports stored either as a list of ints or as [first, last] ranges (host evidence)."""
    spans: list[tuple[int, int]] = []
    if isinstance(value, (list, tuple, set)):
        for item in value:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                try:
                    spans.append((int(item[0]), int(item[1])))
                except (TypeError, ValueError):
                    continue
            else:
                try:
                    spans.append((int(item), int(item)))
                except (TypeError, ValueError):
                    continue
    return PortSet.of(spans)


def rule_ports(rule: dict[str, Any]) -> PortSet:
    """Ports a normalized firewall rule admits; ICMP and port-less protocols map to port 0."""
    protocol = str(rule.get("protocol", "tcp"))
    if protocol not in {"tcp", "udp"}:
        return PortSet.of([(0, 0)])
    start, end = rule.get("port_from"), rule.get("port_to")
    if start is None and isinstance(rule.get("port"), int):
        start = end = rule["port"]
    if start is None:
        return PortSet.full()
    return PortSet.of([(int(start), int(end if end is not None else start))])


def source_class(source: str) -> tuple[str, str] | None:
    """(family, class) for a public source: world, wide, or allowlist. Private sources return None."""
    if source in WORLD.values():
        return ("ipv4" if source == WORLD["ipv4"] else "ipv6"), "world"
    try:
        network = ipaddress.ip_network(source, strict=False)
    except ValueError:
        return None
    family = "ipv4" if network.version == 4 else "ipv6"
    if any(network.version == internal.version and network.subnet_of(internal) for internal in INTERNAL):  # type: ignore[arg-type]
        return None
    return family, ("wide" if network.prefixlen <= WIDE_PREFIX[family] else "allowlist")


Exposure = dict[tuple[str, str, str], PortSet]  # (family, protocol, class) -> ports


def asset_exposure(asset: Asset, edges: Iterable[Edge] = ()) -> Exposure:
    """Effective public ingress of one asset.

    Servers and firewalls use their normalized inbound rules; public load balancers expose their
    service listen ports. Fixture snapshots without rules fall back to Internet `allows` edges.
    `public_interface` edges never count: a public IP alone admits no traffic.
    """
    exposure: Exposure = {}

    def add(key: tuple[str, str, str], ports: PortSet) -> None:
        exposure[key] = exposure.get(key, PortSet()).union(ports)

    props = asset.properties
    if asset.type == "load_balancer":
        if (props.get("public_net") or {}).get("enabled", True):
            for service in props.get("services") or []:
                port = service.get("listen_port")
                if isinstance(port, int):
                    for family in ("ipv4", "ipv6"):
                        add((family, "tcp", "world"), PortSet.of([(port, port)]))
        return exposure
    inbound = props.get("inbound")
    if isinstance(inbound, list):
        for rule in inbound:
            protocol = str(rule.get("protocol", "tcp"))
            for source in rule.get("sources", []) or []:
                classified = source_class(str(source))
                if classified:
                    add((classified[0], protocol, classified[1]), rule_ports(rule))
        return exposure
    for edge in edges:
        if edge.source == "internet" and edge.target == asset.id and edge.relation == "allows":
            ports = PortSet.of([(edge.port, edge.port)]) if edge.port is not None else PortSet.full()
            add(("any", edge.protocol or "tcp", "world"), ports)  # edges carry no address family
    return exposure


def snapshot_exposure(snapshot: Snapshot) -> dict[str, Exposure]:
    edges = list(snapshot.edges)
    return {
        asset.id: exposure
        for asset in snapshot.assets
        if asset.type in {"server", "load_balancer", "service"}
        and (exposure := asset_exposure(asset, edges))
    }


def exposure_growth(before: dict[str, Exposure], after: dict[str, Exposure]) -> list[dict[str, Any]]:
    """Flows allowed after but not before: AFTER_ALLOWED minus BEFORE_ALLOWED, per asset and key."""
    growth = []
    for asset_id, flows in sorted(after.items()):
        previous = before.get(asset_id, {})
        for key, ports in sorted(flows.items()):
            added = ports.difference(previous.get(key, PortSet()))
            if added:
                family, protocol, klass = key
                growth.append(
                    {
                        "asset": asset_id,
                        "family": family,
                        "protocol": protocol,
                        "source_class": klass,
                        "ports": added.describe(),
                        "port_count": added.size(),
                    }
                )
    return growth
