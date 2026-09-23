"""Network topology map: who can send traffic where, rendered as Mermaid, SVG, or JSON.

The map is built only from normalized provider evidence (servers, networks, firewall rules).
Public IP addresses are never rendered; sources are summarized by trust class.
"""

from __future__ import annotations

import ipaddress
from html import escape
from typing import Any

from .models import Asset, Snapshot

# Published at https://www.cloudflare.com/ips/ ; used only to label firewall sources.
CLOUDFLARE_RANGES = tuple(
    ipaddress.ip_network(value)
    for value in (
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
        "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    )
)
TAILSCALE_RANGES = (ipaddress.ip_network("100.64.0.0/10"), ipaddress.ip_network("fd7a:115c:a1e0::/48"))
WORLD = {"0.0.0.0/0", "::/0"}
TAILSCALE_UDP_PORT = 41641
SENSITIVE_PORTS = {22, 2375, 2376, 3306, 5432, 6379, 6443, 9200, 27017}

SOURCE_LABELS = {
    "world": "Internet (any address)",
    "cloudflare": "Cloudflare only",
    "tailscale": "Tailscale tailnet",
    "private": "Private network",
    "allowlist": "Allow-listed addresses",
}

GROUPS = (
    ("edge", "Edge & web", ("edge", "fe", "web", "proxy", "lb", "gateway")),
    ("security", "Identity & secrets", ("vault", "auth", "identity", "secret", "kms")),
    ("data", "Data", ("db", "database", "postgres", "redis", "replica", "warehouse", "data", "storage")),
    ("app", "Applications", ("app", "api", "worker", "service", "bus", "agent")),
)


def _within(source: str, ranges: tuple[Any, ...]) -> bool:
    try:
        network = ipaddress.ip_network(source, strict=False)
    except ValueError:
        return False
    return any(
        network.version == candidate.version and network.subnet_of(candidate)
        for candidate in ranges
    )


def classify_source(source: str, private_ranges: tuple[Any, ...]) -> str:
    if source in WORLD:
        return "world"
    if _within(source, CLOUDFLARE_RANGES):
        return "cloudflare"
    if _within(source, TAILSCALE_RANGES):
        return "tailscale"
    if private_ranges and _within(source, private_ranges):
        return "private"
    return "allowlist"


def _port_text(rule: dict[str, Any]) -> str:
    protocol = str(rule.get("protocol", "tcp"))
    if protocol in {"icmp", "esp", "gre"}:
        return protocol
    start, end = rule.get("port_from"), rule.get("port_to")
    if start is None:
        return f"{protocol}/all"
    return f"{protocol}/{start}" if start == end else f"{protocol}/{start}-{end}"


def _port_sort_key(port: str) -> tuple[int, str]:
    digits = "".join(char for char in port.split("/")[-1].split("-")[0] if char.isdigit())
    return (int(digits) if digits else 1 << 20, port)


def _group(server: Asset) -> str:
    text = " ".join(
        [server.labels.get("role", ""), server.labels.get("service", ""), server.name]
    ).lower()
    tokens = set(text.replace("_", "-").replace(" ", "-").split("-"))
    role = server.labels.get("role", "").lower()
    for key, _title, words in GROUPS:
        if role and any(word == role or role.startswith(word) for word in words):
            return key
    for key, _title, words in GROUPS:
        if tokens & set(words):
            return key
    return "other"


def _sensitive(server: Asset) -> bool:
    return _group(server) in {"security", "data"} and any(
        word in (server.labels.get("role", "") + " " + server.name).lower()
        for word in ("db", "database", "postgres", "redis", "vault", "auth", "identity", "secret")
    )


def build_topology(snapshot: Snapshot) -> dict[str, Any]:
    networks = [asset for asset in snapshot.assets if asset.type == "network"]
    private_ranges = tuple(
        ipaddress.ip_network(str(item.properties["ip_range"]), strict=False)
        for item in networks
        if item.properties.get("ip_range")
    )
    network_names = {item.properties.get("id"): item.name for item in networks}
    volumes = {asset.properties.get("id"): asset for asset in snapshot.assets if asset.type == "volume"}
    servers = []
    for server in sorted(
        (asset for asset in snapshot.assets if asset.type == "server"), key=lambda item: item.name
    ):
        props = server.properties
        ingress: dict[str, list[str]] = {}
        for rule in props.get("inbound", []) or []:
            classes = {classify_source(str(source), private_ranges) for source in rule.get("sources", [])}
            for kind in classes:
                port = _port_text(rule)
                if kind == "world" and rule.get("protocol") == "udp" and rule.get("port_from") == TAILSCALE_UDP_PORT:
                    kind, port = "tailscale", "udp/41641 (WireGuard)"
                ports = ingress.setdefault(kind, [])
                if port not in ports:
                    ports.append(port)
                    ports.sort(key=_port_sort_key)
        world_ports = [port for port in ingress.get("world", []) if port != "icmp"]
        sensitive_world = [
            port
            for port in world_ports
            if port.endswith("/all")
            or any(port == f"tcp/{number}" for number in SENSITIVE_PORTS)
        ]
        exposure = (
            "critical" if sensitive_world or (props.get("public_ip") and not props.get("firewall_attached"))
            else "public" if world_ports
            else "proxied" if ingress.get("cloudflare")
            else "private"
        )
        server_type: dict[str, Any] = props["server_type"] if isinstance(props.get("server_type"), dict) else {}
        location: dict[str, Any] = props["location"] if isinstance(props.get("location"), dict) else {}
        attached = [
            volumes[volume_id] for volume_id in props.get("volumes", []) or [] if volume_id in volumes
        ]
        servers.append(
            {
                "id": server.id,
                "name": server.name,
                "group": _group(server),
                "role": server.labels.get("role") or server.labels.get("service") or "",
                "environment": server.labels.get("environment", ""),
                "type": server_type.get("name", ""),
                "deprecated_type": server_type.get("deprecated") is True,
                "location": location.get("name", ""),
                "status": props.get("status", ""),
                "public_ip": bool(props.get("public_ip")),
                "firewall": bool(props.get("firewall_attached")),
                "networks": [
                    network_names.get(item.get("network"), str(item.get("network")))
                    for item in props.get("private_net", []) or []
                ],
                "volume_gb": sum(int(item.properties.get("size", 0) or 0) for item in attached),
                "backups": bool(props.get("backup_enabled")),
                "delete_protection": bool(props.get("delete_protection")),
                "sensitive": _sensitive(server),
                "ingress": ingress,
                "exposure": exposure,
            }
        )
    return {
        "networks": [
            {"name": item.name, "ip_range": item.properties.get("ip_range", "")} for item in networks
        ],
        "servers": servers,
        "unattached_volumes": [
            asset.name
            for asset in snapshot.assets
            if asset.type == "volume" and not asset.properties.get("server")
        ],
        "collected_at": snapshot.metadata.get("collected_at"),
    }


def _group_title(key: str) -> str:
    return next((title for group, title, _words in GROUPS if group == key), "Other")


def _node_id(name: str) -> str:
    return "n_" + "".join(char if char.isalnum() else "_" for char in name)


def render_mermaid(topology: dict[str, Any]) -> str:
    lines = ["flowchart LR"]
    sources_used = sorted(
        {kind for server in topology["servers"] for kind in server["ingress"] if kind != "private"}
    )
    for kind in sources_used:
        shape = ("((", "))") if kind == "world" else ("([", "])")
        lines.append(f'  src_{kind}{shape[0]}"{SOURCE_LABELS[kind]}"{shape[1]}')
    network_title = ", ".join(f"{net['name']} {net['ip_range']}" for net in topology["networks"]) or "Private network"
    sections = [
        ("net", network_title, [item for item in topology["servers"] if item["networks"]]),
        ("nonet", "No private network", [item for item in topology["servers"] if not item["networks"]]),
    ]
    for section_id, section_title, members in sections:
        if not members:
            continue
        lines.append(f'  subgraph {section_id}["{escape(section_title)}"]')
        groups: dict[str, list[dict[str, Any]]] = {}
        for server in members:
            groups.setdefault(server["group"], []).append(server)
        for key in [group for group, _t, _w in GROUPS] + ["other"]:
            if key not in groups:
                continue
            lines.append(f'    subgraph {section_id}_{key}["{_group_title(key)}"]')
            lines.append("      direction TB")
            for server in groups[key]:
                detail = " · ".join(item for item in (server["role"], server["type"], server["location"]) if item)
                lines.append(f'      {_node_id(server["name"])}["{server["name"]}<br/><small>{escape(detail)}</small>"]')
            lines.append("    end")
        lines.append("  end")
    for server in topology["servers"]:
        for kind, ports in server["ingress"].items():
            if kind in {"private", "tailscale"}:
                continue
            visible = [port for port in ports if port != "icmp"]
            if not visible:
                continue
            arrow = "==>" if kind == "world" else "-->"
            lines.append(f'  src_{kind} {arrow}|"{", ".join(visible)}"| {_node_id(server["name"])}')
    if "tailscale" in sources_used:
        for section_id, _title, members in sections:
            if any("tailscale" in item["ingress"] for item in members):
                lines.append(f'  src_tailscale -.->|"admin & WireGuard"| {section_id}')
    styles = {
        "critical": "fill:#4a1717,stroke:#f87171,color:#fee2e2",
        "public": "fill:#43300f,stroke:#fbbf24,color:#fef3c7",
        "proxied": "fill:#0f3a2e,stroke:#34d399,color:#d1fae5",
        "private": "fill:#13233a,stroke:#60a5fa,color:#dbeafe",
    }
    for exposure, style in styles.items():
        members = [_node_id(item["name"]) for item in topology["servers"] if item["exposure"] == exposure]
        if members:
            lines.append(f"  classDef {exposure} {style}")
            lines.append(f"  class {','.join(members)} {exposure}")
    return "\n".join(lines)


def render_topology_markdown(topology: dict[str, Any]) -> str:
    counts: dict[str, int] = {}
    for server in topology["servers"]:
        counts[server["exposure"]] = counts.get(server["exposure"], 0) + 1
    lines = [
        "# Hetzner Network Map",
        "",
        f"Collected at: {topology.get('collected_at') or 'unknown'} · servers: {len(topology['servers'])} · "
        + " · ".join(f"{key}: {value}" for key, value in sorted(counts.items())),
        "",
        "```mermaid",
        render_mermaid(topology),
        "```",
        "",
        "Exposure: **critical** = sensitive port or all ports open to any address, or no cloud firewall; "
        "**public** = other ports open to any address; **proxied** = reachable only through Cloudflare; "
        "**private** = no public ingress except the Tailscale WireGuard port.",
        "",
        "| Server | Group | Type | Exposure | Public ingress | Private / admin ingress |",
        "|---|---|---|---|---|---|",
    ]
    for server in topology["servers"]:
        public = "; ".join(
            f"{SOURCE_LABELS[kind]}: {', '.join(port for port in ports if port != 'icmp')}"
            for kind, ports in server["ingress"].items()
            if kind in {"world", "cloudflare", "allowlist"} and any(port != "icmp" for port in ports)
        ) or ("none (ICMP only)" if "icmp" in server["ingress"].get("world", []) else "none")
        private = "; ".join(
            f"{SOURCE_LABELS[kind]}: {', '.join(ports)}"
            for kind, ports in server["ingress"].items()
            if kind in {"private", "tailscale"}
        ) or "none"
        server_type = server["type"] + (" (deprecated)" if server["deprecated_type"] else "")
        lines.append(
            f"| {server['name']} | {_group_title(server['group'])} | {server_type} | {server['exposure']} | {public} | {private} |"
        )
    if topology["unattached_volumes"]:
        lines.extend(["", "Unattached volumes: " + ", ".join(topology["unattached_volumes"])])
    lines.extend(["", "Public IP addresses are intentionally omitted. The map shows provider firewall intent, not host or application controls."])
    return "\n".join(lines)


# ---------------------------------------------------------------- SVG rendering

_SVG_COLORS = {
    "bg": "#0b1220",
    "panel": "#0f1a2e",
    "panel_stroke": "#23324d",
    "text": "#e5edf7",
    "muted": "#8aa0bd",
    "critical": "#f87171",
    "public": "#fde047",
    "proxied": "#34d399",
    "private": "#60a5fa",
    "world": "#fde047",
    "cloudflare": "#fb923c",
    "tailscale": "#a78bfa",
    "allowlist": "#94a3b8",
}


def render_svg(topology: dict[str, Any], title: str = "Hetzner network map") -> str:
    """Render a dependency-free SVG: trust sources on the left, servers grouped by role."""
    card_w, card_h, gap_x, gap_y, lane_h = 214, 64, 18, 16, 16
    left_w, margin, per_row = 230, 32, 5
    x0 = margin + left_w + 56
    servers = topology["servers"]
    public_kinds = ("world", "cloudflare", "allowlist")
    edges = [
        (kind, server["name"], [port for port in server["ingress"][kind] if port != "icmp"])
        for server in servers
        for kind in public_kinds
        if any(port != "icmp" for port in server["ingress"].get(kind, []))
    ]
    network_title = ", ".join(f"{net['name']} · {net['ip_range']}" for net in topology["networks"])
    sections = [
        (f"PRIVATE NETWORK  {network_title}", [item for item in servers if item["networks"]]),
        ("NO PRIVATE NETWORK", [item for item in servers if not item["networks"]]),
    ]
    sections = [(name, members) for name, members in sections if members]

    # Layout pass: panels, group headings, one routing lane per public edge above its row.
    y = margin + 84
    panels: list[tuple[str, int, int]] = []
    headings: list[tuple[str, int]] = []
    positions: dict[str, tuple[int, int]] = {}
    for section_title, members in sections:
        top = y
        y += 40
        groups: dict[str, list[dict[str, Any]]] = {}
        for server in members:
            groups.setdefault(server["group"], []).append(server)
        for key in [group for group, _t, _w in GROUPS] + ["other"]:
            if key not in groups:
                continue
            headings.append((_group_title(key).upper(), y))
            y += 28
            for start in range(0, len(groups[key]), per_row):
                chunk = groups[key][start : start + per_row]
                names = {item["name"] for item in chunk}
                lanes = sum(1 for _kind, name, _p in edges if name in names)
                y += lanes * lane_h + (10 if lanes else 0)
                for index, server in enumerate(chunk):
                    positions[server["name"]] = (x0 + index * (card_w + gap_x), y)
                y += card_h + gap_y
            y += 10
        panels.append((section_title, top, y - top))
        y += 24
    width = x0 + per_row * (card_w + gap_x) + margin
    height = y + margin - 8
    colors = _SVG_COLORS
    out: list[str] = []
    add = out.append
    add(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" font-family="ui-sans-serif, -apple-system, Segoe UI, Helvetica, Arial, sans-serif">')
    add(f'<rect width="100%" height="100%" rx="16" fill="{colors["bg"]}"/>')
    add('<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="context-stroke"/></marker></defs>')
    add(f'<text x="{margin}" y="{margin + 16}" font-size="22" font-weight="700" fill="{colors["text"]}">{escape(title)}</text>')
    counts: dict[str, int] = {}
    for server in servers:
        counts[server["exposure"]] = counts.get(server["exposure"], 0) + 1
    summary = f"{len(servers)} servers · " + " · ".join(f"{counts.get(key, 0)} {key}" for key in ("critical", "public", "proxied", "private"))
    add(f'<text x="{margin}" y="{margin + 42}" font-size="13" fill="{colors["muted"]}">{escape(summary)} · read-only API evidence · public IPs omitted</text>')
    legend_x = width - margin - 4 * 104
    for index, key in enumerate(("critical", "public", "proxied", "private")):
        add(f'<rect x="{legend_x + index * 104}" y="{margin + 6}" width="12" height="12" rx="3" fill="none" stroke="{colors[key]}" stroke-width="2"/>')
        add(f'<text x="{legend_x + index * 104 + 18}" y="{margin + 16}" font-size="12" fill="{colors["muted"]}">{key}</text>')
    for section_title, top, panel_h in panels:
        add(f'<rect x="{x0 - 20}" y="{top}" width="{width - x0 - margin + 20}" height="{panel_h}" rx="14" fill="{colors["panel"]}" stroke="{colors["panel_stroke"]}"/>')
        add(f'<text x="{x0}" y="{top + 26}" font-size="13" font-weight="600" letter-spacing="0.5" fill="{colors["muted"]}">{escape(section_title)}</text>')
    for heading, heading_y in headings:
        add(f'<text x="{x0}" y="{heading_y + 16}" font-size="11.5" font-weight="700" letter-spacing="1" fill="{colors["muted"]}">{escape(heading)}</text>')
    # Trust sources.
    kinds = [kind for kind in ("world", "cloudflare", "allowlist", "tailscale") if any(kind in item["ingress"] for item in servers)]
    source_pos: dict[str, tuple[int, int]] = {}
    source_y = margin + 84
    for kind in kinds:
        color = colors[kind]
        add(f'<rect x="{margin}" y="{source_y}" width="{left_w}" height="52" rx="26" fill="{colors["panel"]}" stroke="{color}" stroke-width="2"/>')
        add(f'<text x="{margin + left_w / 2}" y="{source_y + 31}" text-anchor="middle" font-size="14" font-weight="600" fill="{color}">{escape(SOURCE_LABELS[kind])}</text>')
        source_pos[kind] = (margin + left_w, source_y + 26)
        source_y += 80
    if "tailscale" in source_pos:
        tx, ty = source_pos["tailscale"]
        reached = sum(1 for item in servers if "tailscale" in item["ingress"])
        add(f'<text x="{margin + left_w / 2}" y="{ty + 44}" text-anchor="middle" font-size="11.5" fill="{colors["tailscale"]}">admin + WireGuard → {reached} servers</text>')
    # Public edges: source → gutter → lane above the target row → down into the card.
    gutters = {kind: x0 - 44 + index * 8 for index, kind in enumerate(public_kinds)}
    lane_used: dict[int, int] = {}
    for kind, name, ports in edges:
        if name not in positions or kind not in source_pos:
            continue
        card_x, card_y = positions[name]
        start_x, start_y = source_pos[kind]
        used = lane_used.get(card_y, 0)
        lane_used[card_y] = used + 1
        lane_y = card_y - 12 - used * lane_h
        target_x = card_x + card_w - 30
        color = colors[kind]
        add(
            f'<path d="M {start_x} {start_y} L {gutters[kind]} {start_y} L {gutters[kind]} {lane_y} L {target_x} {lane_y} L {target_x} {card_y}" '
            f'stroke="{color}" stroke-width="{2.4 if kind == "world" else 1.8}" fill="none" stroke-linejoin="round" marker-end="url(#arrow)"/>'
        )
        label = ", ".join(ports)
        add(f'<text x="{target_x - 8}" y="{lane_y - 4}" text-anchor="end" font-size="11" font-weight="600" fill="{color}">{escape(label)}</text>')
    for server in servers:
        card_x, card_y = positions[server["name"]]
        stroke = colors[server["exposure"]]
        add(f'<rect x="{card_x}" y="{card_y}" width="{card_w}" height="{card_h}" rx="10" fill="#111f36" stroke="{stroke}" stroke-width="1.6"/>')
        add(f'<text x="{card_x + 12}" y="{card_y + 22}" font-size="14" font-weight="700" fill="{colors["text"]}">{escape(server["name"])}</text>')
        detail = " · ".join(item for item in (server["role"], server["type"], server["location"]) if item)
        add(f'<text x="{card_x + 12}" y="{card_y + 40}" font-size="11.5" fill="{colors["muted"]}">{escape(detail[:34])}</text>')
        badges = []
        if server["sensitive"]:
            badges.append(("sensitive", colors["critical"]))
        if server["volume_gb"]:
            badges.append((f"{server['volume_gb']} GB vol", colors["muted"]))
        if server["deprecated_type"]:
            badges.append(("deprecated type", colors["public"]))
        if server["delete_protection"]:
            badges.append(("protected", colors["proxied"]))
        badge_x = card_x + 12
        for text, color in badges[:3]:
            add(f'<text x="{badge_x}" y="{card_y + 56}" font-size="10.5" font-weight="600" fill="{color}">{escape(text)}</text>')
            badge_x += 10 + int(len(text) * 6.2)
    add("</svg>")
    return "\n".join(out)
