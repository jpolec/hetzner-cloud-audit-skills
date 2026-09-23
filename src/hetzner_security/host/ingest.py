"""Merge host evidence bundles into a snapshot.

For each server the bundle turns `cloud_path_present` into an answer: a public flow is reachable
only where the cloud firewall, the host firewall, and a listener all admit it. Docker-published
ports are the exception to the host firewall: Docker DNATs them before UFW's or nftables' input
rules run, so they are admitted unless a DOCKER-USER rule filters them.
"""

from __future__ import annotations

import ipaddress
from copy import deepcopy
from pathlib import Path
from typing import Any

from ..flows import PortSet, asset_exposure, port_set
from ..models import Asset, Edge, Evidence, Snapshot
from .parsers import (
    evaluate_chain,
    iptables_filters,
    parse_docker,
    parse_docker_user,
    parse_iptables,
    parse_listeners,
    parse_meta,
    parse_nftables,
    parse_pg_hba,
    parse_redis,
    parse_sshd,
    parse_ufw,
    present,
    split_sections,
)
from .script import BUNDLE_VERSION

PUBLIC_BINDS = {"wildcard", "public"}


def _reachable_privately(bind: str, address: str, network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    """A listener answers on the Hetzner private network if it binds everywhere or to an address inside it.

    A Tailscale (100.64.0.0/10) or Docker bridge address is internal, but not on the Hetzner network.
    """
    if bind == "wildcard":
        return True
    try:
        return ipaddress.ip_address(address.strip("[]").split("%")[0]) in network
    except ValueError:
        return False


def parse_bundle(text: str) -> dict[str, Any]:
    sections = split_sections(text)
    return {
        "bundle_version": BUNDLE_VERSION,
        "meta": parse_meta(sections.get("meta", "")),
        "sections": sorted(name for name, value in sections.items() if present(value) and name not in {"meta", "end"}),
        "complete": "end" in sections,
        "ufw": parse_ufw(sections.get("ufw", "")),
        "nftables": parse_nftables(sections.get("nftables", "")),
        "iptables": parse_iptables(sections.get("iptables", "")),
        "ip6tables": parse_iptables(sections.get("ip6tables", "")),
        "docker_user": parse_docker_user(sections.get("docker_user", "")),
        "listeners": parse_listeners(sections.get("listeners", "")),
        "sshd": parse_sshd(sections.get("sshd", "")),
        "agents": sorted({line.strip() for line in sections.get("agents", "").splitlines() if line.strip() and " " not in line.strip()}),
        "docker": parse_docker(sections.get("docker", "")),
        "pg_hba": parse_pg_hba(sections.get("pg_hba", "")),
        "redis": parse_redis(sections.get("redis", "")),
    }


def _host_allowed(bundle: dict[str, Any], protocol: str, client: str, private: bool = False) -> tuple[str, PortSet | None, bool]:
    """(engine, ports the host firewall admits from ``client``, partial). None means not evidenced."""
    ufw = bundle["ufw"]
    if ufw.get("installed") and ufw.get("error"):
        return "unknown", None, False
    if ufw.get("installed") and ufw.get("active"):
        if ufw.get("unparsed"):
            return "ufw", None, False
        allowed, partial = evaluate_chain(ufw, protocol, client, private)
        return "ufw", allowed, partial
    nft = bundle["nftables"]
    legacy = bundle["ip6tables" if ":" in client else "iptables"]
    if nft.get("input_chains"):
        result: PortSet | None = None
        partial = False
        for chain in nft["input_chains"]:
            allowed, chain_partial = evaluate_chain(chain, protocol, client, private)
            if allowed is None:
                return "nftables", None, partial
            partial = partial or chain_partial
            result = allowed if result is None else result.intersection(allowed)
        return "nftables", result, partial
    if legacy.get("installed") and not legacy.get("error") and iptables_filters(legacy):
        allowed, partial = evaluate_chain(legacy, protocol, client, private)
        return "iptables", allowed, partial
    # "Nothing filters" must be observed, not inferred from missing output.
    nft_empty = nft.get("installed") and not nft.get("error") and "input_chains" in nft
    legacy_empty = legacy.get("installed") and not legacy.get("error") and "rules" in legacy
    if (nft_empty or not nft.get("installed")) and (legacy_empty or not legacy.get("installed")) and (nft_empty or legacy_empty):
        return "none", PortSet.full(), False
    return "unknown", None, False


def _world(bundle: dict[str, Any], protocol: str) -> tuple[str, PortSet | None]:
    """Both address families: a port is Internet-reachable over IPv4 or IPv6."""
    engine, v4, _ = _host_allowed(bundle, protocol, "0.0.0.0/0")
    _, v6, _ = _host_allowed(bundle, protocol, "::/0")
    return engine, (None if v4 is None or v6 is None else v4.union(v6))


def _ranges(ports: PortSet | None) -> list[list[int]] | None:
    return None if ports is None else [[first, last] for first, last in ports]


def _match_server(snapshot: Snapshot, name: str) -> Asset | None:
    for asset in snapshot.assets:
        if asset.type != "server":
            continue
        if name in {asset.name, asset.id, asset.id.rsplit(":", 1)[-1]}:
            return asset
    return None


def _private_client(snapshot: Snapshot, server: Asset) -> str:
    assets = snapshot.asset_map()
    for private_net in server.properties.get("private_net") or []:
        network = assets.get(f"hcloud:network:{private_net.get('network')}")
        if network and network.properties.get("ip_range"):
            return str(network.properties["ip_range"])
    return "10.0.0.0/8"


def apply_host_bundle(snapshot: Snapshot, bundle: dict[str, Any], source: str) -> dict[str, Any]:
    """Mutate ``snapshot`` with one parsed bundle; return a status record for metadata."""
    name = bundle["meta"].get("server", "")
    server = _match_server(snapshot, name)
    status = {"source": source, "server": name, "sections": bundle["sections"], "complete": bundle["complete"]}
    if server is None:
        return {**status, "status": "unmatched", "note": "no server with this name or ID in the snapshot"}

    docker = bundle["docker"]
    docker_known = not docker.get("error")
    published = [item | {"container": container["name"]} for container in docker.get("containers") or [] for item in container["published"]]
    docker_filters = bundle["docker_user"].get("filters")
    listeners = bundle["listeners"].get("listeners")
    private_client = _private_client(snapshot, server)
    private_network = ipaddress.ip_network(private_client, strict=False)

    props = server.properties
    engine = "unknown"
    for protocol, suffix in (("tcp", ""), ("udp", "_udp")):
        engine, world = _world(bundle, protocol)
        _, private, partial = _host_allowed(bundle, protocol, private_client, private=True)
        docker_public = PortSet.of(
            [(item["host_port"], item["host_port"]) for item in published if item["protocol"] == protocol and item["bind"] in PUBLIC_BINDS]
        )
        docker_private = PortSet.of(
            [(item["host_port"], item["host_port"]) for item in published
             if item["protocol"] == protocol and _reachable_privately(item["bind"], item["host_ip"], private_network)]
        )
        # Docker's DNAT skips the input chain; if Docker state or DOCKER-USER filtering is unknown, so is the host's answer.
        docker_unknown = not docker_known or (docker_filters is not False and bool(docker_public or docker_private))
        if world is not None and not docker_unknown:
            props[f"host_firewall_allow{suffix}_ports"] = _ranges(world.union(docker_public))
        if private is not None and not docker_unknown:
            props[f"host_firewall_private_allow{suffix}_ports"] = _ranges(private.union(docker_private))
            props[f"host_firewall_private{suffix}_partial"] = partial
        if listeners is not None:
            public_ports = {item["port"] for item in listeners if item["protocol"] == protocol and item["bind"] in PUBLIC_BINDS}
            private_ports = {item["port"] for item in listeners
                             if item["protocol"] == protocol and _reachable_privately(item["bind"], item["address"], private_network)}
            props[f"listening{suffix}_ports"] = sorted(public_ports | {port for port, _ in docker_public})
            props[f"private_listening{suffix}_ports"] = sorted(private_ports | {port for port, _ in docker_private})
        if protocol == "tcp":
            unparsed = bundle["ufw"].get("unparsed")
            props["host_firewall"] = {
                "engine": engine,
                # An engine whose rules admit every port from the Internet filters nothing; unknown is not active.
                "active": engine in {"ufw", "nftables", "iptables"} and world is not None and world != PortSet.full(),
                "known": world is not None,
                "default_incoming": bundle["ufw"].get("default_incoming") if engine == "ufw" else None,
                "world_tcp": world.describe() if world is not None else None,
                "world_tcp_ranges": _ranges(world),
                "unparsed_rules": len(unparsed) if isinstance(unparsed, list) else 0,
            }
    props["host_agents"] = bundle.get("agents") or []
    props["docker_published"] = published
    props["docker_user_filters"] = docker_filters
    if listeners is not None:
        props["listeners"] = listeners
    if bundle["sshd"]:
        props["sshd"] = bundle["sshd"]
    props["host_evidence"] = {
        "bundle_version": bundle["bundle_version"],
        "collected_at": bundle["meta"].get("collected_at"),
        "source": source,
        "sections": bundle["sections"],
        "complete": bundle["complete"],
        "firewall_engine": engine,
        "os": " ".join(filter(None, (bundle["meta"].get("id"), bundle["meta"].get("version_id")))) or None,
    }

    world_exposure = asset_exposure(server, snapshot.edges)
    cloud_world = {
        protocol: PortSet.of(
            [span for (family, proto, klass), ports in world_exposure.items() if proto == protocol and klass == "world" for span in ports]
        )
        for protocol in ("tcp", "udp")
    }
    if props.get("public_ip", True) and props.get("firewall_attached") is False:
        cloud_world = {"tcp": PortSet.full(), "udp": PortSet.full()}  # no Cloud Firewall: everything passes
    environment = server.labels.get("environment")
    suffix_id = server.id.rsplit(":", 1)[-1]

    def add(asset: Asset) -> None:
        snapshot.assets[:] = [item for item in snapshot.assets if item.id != asset.id]
        snapshot.assets.append(asset)
        snapshot.edges.append(Edge(server.id, asset.id, "runs"))

    for container in docker["containers"]:
        asset = Asset(
            f"host:container:{suffix_id}:{container['name']}",
            "container",
            container["name"],
            {**container, "server": server.id},
            {"environment": environment} if environment else {},
            "host_bundle",
        )
        add(asset)
        for item in container["published"]:
            port, protocol = item["host_port"], item["protocol"]
            if item["bind"] in PUBLIC_BINDS and port in cloud_world.get(protocol, PortSet()):
                evidence = (
                    Evidence("host_bundle", "docker_published", asset.id, item, "docker inspect .NetworkSettings.Ports"),
                    Evidence("host_bundle", "listening_socket", asset.id, {"protocol": protocol, "port": port}),
                    Evidence("host_bundle", "host_firewall_allow", server.id, {"protocol": protocol, "port": port, "reason": "docker_bypass"}),
                )
                snapshot.edges.append(Edge("internet", asset.id, "publishes", protocol, port, evidence))

    reachable_tcp = cloud_world["tcp"].intersection(
        PortSet.of([(p, p) for p in props.get("listening_ports", [])])
    ).intersection(port_set(props.get("host_firewall_allow_ports")))
    # Cloud Firewalls do not filter private networks: host firewall and listener alone decide.
    private_reachable = PortSet.of([(p, p) for p in props.get("private_listening_ports", [])]).intersection(
        port_set(props.get("host_firewall_private_allow_ports"))
    )
    for file_name, entries in bundle["pg_hba"].get("files", {}).items():
        pg = Asset(
            f"host:postgres:{suffix_id}:{Path(file_name).parent.parent.name or 'main'}",
            "postgres",
            f"{server.name} postgres",
            {"pg_hba": entries, "pg_hba_file": file_name, "port": 5432, "server": server.id},
            {"environment": environment} if environment else {},
            "host_bundle",
        )
        add(pg)
        if 5432 in reachable_tcp:
            snapshot.edges.append(Edge("internet", pg.id, "allows", "tcp", 5432, _reach_evidence(server, pg, 5432)))
        snapshot.edges.extend(_private_edges(server, pg, 5432, private_reachable))
    redis = bundle["redis"]
    if redis.get("running") and "bind" in redis:
        binds = [value.lstrip("-") for value in redis["bind"]] or ["*"]
        rd = Asset(
            f"host:redis:{suffix_id}",
            "redis",
            f"{server.name} redis",
            {**{key: redis[key] for key in ("protected_mode", "requirepass", "acl_enabled")}, "bind": binds, "port": 6379, "server": server.id},
            {"environment": environment} if environment else {},
            "host_bundle",
        )
        add(rd)
        if 6379 in reachable_tcp:
            snapshot.edges.append(Edge("internet", rd.id, "allows", "tcp", 6379, _reach_evidence(server, rd, 6379)))
        snapshot.edges.extend(_private_edges(server, rd, 6379, private_reachable))
    return {**status, "status": "merged", "asset": server.id}


def _private_edges(server: Asset, target: Asset, port: int, reachable: PortSet) -> list[Edge]:
    if port not in reachable:
        return []
    evidence = (
        Evidence("hcloud_api", "private_network_unfiltered", server.id, {"port": port}, "properties.private_net"),
        Evidence("host_bundle", "listening_socket", server.id, {"protocol": "tcp", "port": port}, "properties.private_listening_ports"),
        Evidence("host_bundle", "host_firewall_allow", server.id, {"protocol": "tcp", "port": port}, "properties.host_firewall_private_allow_ports"),
    )
    return [
        Edge(f"hcloud:network:{item.get('network')}", target.id, "allows", "tcp", port, evidence)
        for item in server.properties.get("private_net") or []
        if item.get("network") is not None
    ]


def _reach_evidence(server: Asset, target: Asset, port: int) -> tuple[Evidence, ...]:
    return (
        Evidence("hcloud_api", "firewall_rule", server.id, {"protocol": "tcp", "port": port}, "properties.inbound"),
        Evidence("host_bundle", "listening_socket", server.id, {"protocol": "tcp", "port": port}, "properties.listening_ports"),
        Evidence("host_bundle", "host_firewall_allow", server.id, {"protocol": "tcp", "port": port}, "properties.host_firewall_allow_ports"),
    )


def apply_host_bundles(snapshot: Snapshot, paths: list[Path]) -> Snapshot:
    result = deepcopy(snapshot)
    statuses = []
    for path in paths:
        bundle = parse_bundle(path.read_text(encoding="utf-8", errors="replace"))
        statuses.append(apply_host_bundle(result, bundle, path.name))
    result.metadata["host_bundles"] = statuses
    return result
