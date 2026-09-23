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


def public_families(asset: Asset) -> set[str]:
    """Address families in which a server has a public interface.

    Without one, a world-open firewall rule admits nothing from the Internet. Snapshots that only
    record ``public_ip`` count both families; assets that are not servers are treated as public.
    """
    props = asset.properties
    if asset.type != "server":
        return {"ipv4", "ipv6"}
    if "public_ipv4" in props or "public_ipv6" in props:
        return {family for family in ("ipv4", "ipv6") if props.get(f"public_{family}")}
    return {"ipv4", "ipv6"} if props.get("public_ip", True) else set()


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
    families = public_families(asset)
    if not families:
        return exposure  # no public interface: no Internet exposure, whatever the rules say
    inbound = props.get("inbound")
    if isinstance(inbound, list):
        for rule in inbound:
            protocol = str(rule.get("protocol", "tcp"))
            for source in rule.get("sources", []) or []:
                classified = source_class(str(source))
                if classified and classified[0] in families:
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


# ---------------------------------------------------------------- exact flow space (for diff)
#
# Exposure as a set of rectangles: source addresses (integer interval) × destination ports, per
# (address family, protocol). `After - Before` is computed exactly, so widening 1.2.3.4/32 to
# 1.2.3.0/24, or swapping one trusted /32 for another, is a change even when the source class
# (world / wide / allow-list) stays the same. Classification happens after the difference.

Rect = tuple[int, int, int, int]  # source first, source last, port first, port last
FAMILY_BITS = {"ipv4": 32, "ipv6": 128, "any": 0}  # "any": fixture edges without an address family
FlowSpace = dict[tuple[str, str], list[Rect]]  # (family, protocol) -> rectangles


def _rect_minus(a: Rect, b: Rect) -> list[Rect]:
    """a minus b as up to four disjoint rectangles."""
    s1, s2, p1, p2 = a
    t1, t2, q1, q2 = b
    if t2 < s1 or t1 > s2 or q2 < p1 or q1 > p2:
        return [a]
    pieces: list[Rect] = []
    if s1 < t1:
        pieces.append((s1, t1 - 1, p1, p2))
    if t2 < s2:
        pieces.append((t2 + 1, s2, p1, p2))
    mid1, mid2 = max(s1, t1), min(s2, t2)
    if p1 < q1:
        pieces.append((mid1, mid2, p1, q1 - 1))
    if q2 < p2:
        pieces.append((mid1, mid2, q2 + 1, p2))
    return pieces


# Hetzner allows 5 firewalls x 500 rules per server; with source lists this stays well below the cap.
# Measured (sweep, overlapping checkerboard): 500 rules per side ~0.2 s, 2,500 per side ~5 s, memory linear.
MAX_FLOW_RECTS = 200_000


Slab = tuple[int, int, PortSet]  # source first, source last, ports allowed in that source range


def space_minus_slabs(after: list[Rect], before: list[Rect]) -> list[Slab]:
    """Exact ``after - before`` as source slabs, by sweeping the source axis.

    Source boundaries split the address line into slabs; in each slab the allowed ports are one
    PortSet (after minus before), and adjacent slabs with equal ports are merged. The number of
    slabs is at most twice the number of rules, so crafted rule sets cannot blow up memory.
    """
    if not after:
        return []
    if len(after) + len(before) > MAX_FLOW_RECTS:
        raise ValueError(f"more than {MAX_FLOW_RECTS} rule/source combinations on one asset; refusing to diff exactly")
    events: dict[int, list[tuple[int, bool, int]]] = {}  # point -> (+1/-1, is_after, index)
    for is_after, rects in ((True, after), (False, before)):
        for index, rect in enumerate(rects):
            events.setdefault(rect[0], []).append((1, is_after, index))
            events.setdefault(rect[1] + 1, []).append((-1, is_after, index))
    active: dict[bool, set[int]] = {True: set(), False: set()}
    slabs: list[Slab] = []
    points = sorted(events)
    for position, point in enumerate(points[:-1]):
        for change, is_after, index in events[point]:
            (active[is_after].add if change > 0 else active[is_after].discard)(index)
        if not active[True]:
            continue
        ports = PortSet.of([(after[i][2], after[i][3]) for i in active[True]])
        if active[False]:
            ports = ports.difference(PortSet.of([(before[i][2], before[i][3]) for i in active[False]]))
        if not ports:
            continue
        first, last = point, points[position + 1] - 1
        if slabs and slabs[-1][1] == first - 1 and slabs[-1][2] == ports:
            slabs[-1] = (slabs[-1][0], last, ports)
        else:
            slabs.append((first, last, ports))
    return slabs


def space_minus(after: list[Rect], before: list[Rect]) -> list[Rect]:
    """``after - before`` as rectangles (slabs expanded); raises when the result is huge."""
    rects: list[Rect] = []
    for first, last, ports in space_minus_slabs(after, before):
        rects.extend((first, last, p1, p2) for p1, p2 in ports)
        if len(rects) > MAX_FLOW_RECTS:
            raise ValueError(f"flow space exceeds {MAX_FLOW_RECTS} rectangles; use space_minus_slabs")
    return rects


def asset_flowspace(asset: Asset, edges: Iterable[Edge] = ()) -> FlowSpace:
    """Exact public ingress space of one asset (public sources only; internal ranges excluded)."""
    space: FlowSpace = {}
    families = public_families(asset)
    props = asset.properties

    def add(family: str, protocol: str, network: ipaddress.IPv4Network | ipaddress.IPv6Network, ports: PortSet) -> None:
        for first, last in ports:
            space.setdefault((family, protocol), []).append(
                (int(network.network_address), int(network.broadcast_address), first, last)
            )

    if asset.type == "load_balancer":
        if (props.get("public_net") or {}).get("enabled", True):
            for service in props.get("services") or []:
                port = service.get("listen_port")
                if isinstance(port, int):
                    add("ipv4", "tcp", ipaddress.ip_network(WORLD["ipv4"]), PortSet.of([(port, port)]))
                    add("ipv6", "tcp", ipaddress.ip_network(WORLD["ipv6"]), PortSet.of([(port, port)]))
        return space
    if not families:
        return space
    inbound = props.get("inbound")
    if isinstance(inbound, list):
        for rule in inbound:
            protocol = str(rule.get("protocol", "tcp"))
            for source in rule.get("sources", []) or []:
                if source_class(str(source)) is None:
                    continue  # internal range: not Internet exposure
                network = ipaddress.ip_network(str(source), strict=False)
                family = "ipv4" if network.version == 4 else "ipv6"
                if family in families:
                    add(family, protocol, network, rule_ports(rule))
        return space
    for edge in edges:
        if edge.source == "internet" and edge.target == asset.id and edge.relation == "allows":
            ports = PortSet.of([(edge.port, edge.port)]) if edge.port is not None else PortSet.full()
            for first, last in ports:  # the whole Internet, family unknown
                space.setdefault(("any", edge.protocol or "tcp"), []).append((0, 0, first, last))
    return space


def snapshot_flowspace(snapshot: Snapshot) -> dict[str, FlowSpace]:
    edges = list(snapshot.edges)
    return {
        asset.id: space
        for asset in snapshot.assets
        if asset.type in {"server", "load_balancer", "service"} and (space := asset_flowspace(asset, edges))
    }


def _summarize_sources(intervals: list[tuple[int, int]], family: str) -> tuple[list[str], int]:
    """CIDRs covering the source intervals (first few) and the number of addresses."""
    if family == "any":
        return ["any"], 0
    merged: list[list[int]] = []
    for first, last in sorted(set(intervals)):
        if merged and first <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], last)
        else:
            merged.append([first, last])
    make = ipaddress.IPv4Address if family == "ipv4" else ipaddress.IPv6Address
    cidrs: list[str] = []
    for first, last in merged:
        cidrs.extend(str(net) for net in ipaddress.summarize_address_range(make(first), make(last)))
        if len(cidrs) > 8:
            break
    return cidrs, sum(last - first + 1 for first, last in merged)


def classify_space(intervals: list[tuple[int, int]], family: str, sources: list[str], count: int) -> str:
    """Risk class of a flow-space difference: world, wide, edge:<provider>, or allowlist."""
    bits = FAMILY_BITS[family]
    if family == "any" or any(first == 0 and last == 2**bits - 1 for first, last in intervals):
        return "world"
    if count >= 2 ** (bits - WIDE_PREFIX[family]):
        return "wide"
    from .providers import edge_provider  # late import: providers imports nothing from flows

    providers = {edge_provider(cidr) for cidr in sources}
    if sources and len(providers) == 1 and None not in providers:
        return f"edge:{providers.pop()}"
    return "allowlist"


def flowspace_growth(before: dict[str, FlowSpace], after: dict[str, FlowSpace]) -> list[dict[str, Any]]:
    """Exact AFTER minus BEFORE per asset, family, and protocol, classified by risk afterwards."""
    growth = []
    for asset_id, space in sorted(after.items()):
        previous = before.get(asset_id, {})
        for key, rects in sorted(space.items()):
            slabs = space_minus_slabs(rects, previous.get(key, []))
            if not slabs:
                continue
            family, protocol = key
            intervals = [(first, last) for first, last, _ports in slabs]
            sources, count = _summarize_sources(intervals, family)
            ports = PortSet()
            for _first, _last, slab_ports in slabs:
                ports = ports.union(slab_ports)
            growth.append({
                "asset": asset_id,
                "family": family,
                "protocol": protocol,
                "source_class": classify_space(intervals, family, sources, count),
                "sources": sources,
                "source_addresses": count,
                "ports": ports.describe(),
                "port_count": ports.size(),
            })
    return growth


def egress_flowspace(asset: Asset) -> FlowSpace:
    """Internet destinations × ports a server may connect to, as the Cloud Firewall allows.

    No firewall, or no outbound rule in the attached firewalls, means all egress is allowed; with at
    least one outbound rule, only the listed destinations and ports are (Hetzner's implicit deny).
    """
    space: FlowSpace = {}
    props = asset.properties
    if asset.type != "server" or not public_families(asset):
        return space  # without a public interface there is no direct path to the Internet
    outbound = props.get("outbound") or []
    if not props.get("firewall_attached") or not outbound:
        for family in public_families(asset):
            network = ipaddress.ip_network(WORLD[family])
            for protocol in ("tcp", "udp"):
                space.setdefault((family, protocol), []).append((int(network.network_address), int(network.broadcast_address), 0, MAX_PORT))
        return space
    for rule in outbound:
        protocol = str(rule.get("protocol", "tcp"))
        for destination in rule.get("destinations", []) or []:
            if source_class(str(destination)) is None:
                continue
            network = ipaddress.ip_network(str(destination), strict=False)
            family = "ipv4" if network.version == 4 else "ipv6"
            if family in public_families(asset):
                for first, last in rule_ports(rule):
                    space.setdefault((family, protocol), []).append((int(network.network_address), int(network.broadcast_address), first, last))
    return space


def egress_summary(asset: Asset) -> dict[str, Any]:
    """unrestricted (all ports to the whole Internet), limited, or none, with the allowed TCP/UDP ports."""
    space = egress_flowspace(asset)
    if not space:
        return {"state": "none", "ports": {}}
    world = {key: rects for key, rects in space.items() if any(first == 0 and last == 2 ** FAMILY_BITS[key[0]] - 1 for first, last, _a, _b in rects)}
    ports = {f"{family}/{protocol}": PortSet.of([(p1, p2) for _s1, _s2, p1, p2 in rects]).describe() for (family, protocol), rects in world.items()}
    unrestricted = any(value == "all" for value in ports.values())
    return {"state": "unrestricted" if unrestricted else "limited", "ports": ports}
