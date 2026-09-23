"""Cloud-architecture style SVG for a Hetzner topology (in the spirit of AWS/OCI diagrams).

Layout: trust sources on the left; a network-zone boundary containing the private network
(VPC equivalent) and its subnet; location columns (like availability zones) crossed by role
tiers; servers outside any private network and Storage Boxes in a separate band. A summary
header and a legend frame the diagram. Public IP addresses are never rendered.
"""

from __future__ import annotations

import math
from html import escape
from typing import Any

from .topology import GROUPS

THEMES: dict[str, dict[str, str]] = {
    "light": {
        "bg": "#f4f4f4", "surface": "#ffffff", "line": "#e3e3e3", "text": "#1f1f1f", "muted": "#6b6b6b",
        "zone": "#8a8a8a", "vpc": "#1f9d55", "vpc_fill": "#f6fbf8", "location": "#2f6fdb", "band": "#fafafa",
        "critical": "#d50c2d", "public": "#d98e04", "proxied": "#f38020", "private": "#2f6fdb",
        "world": "#d50c2d", "cloudflare": "#f38020", "tailscale": "#6d4fc2", "allowlist": "#7a7a7a",
    },
    "dark": {
        "bg": "#0b1220", "surface": "#111f36", "line": "#23324d", "text": "#e5edf7", "muted": "#8aa0bd",
        "zone": "#8aa0bd", "vpc": "#34d399", "vpc_fill": "#0f1a2e", "location": "#60a5fa", "band": "#0f1a2e",
        "critical": "#f87171", "public": "#fde047", "proxied": "#fb923c", "private": "#60a5fa",
        "world": "#f87171", "cloudflare": "#fb923c", "tailscale": "#a78bfa", "allowlist": "#94a3b8",
    },
}
CATEGORY = {
    "edge": ("#7c4dff", "globe"),
    "app": ("#e8710a", "server"),
    "data": ("#2f6fdb", "database"),
    "security": ("#d50c2d", "shield"),
    "other": ("#6b7280", "server"),
    "storage": ("#0f8b8d", "archive"),
}
LOCATION_NAMES = {
    "fsn1": "Falkenstein", "nbg1": "Nuremberg", "hel1": "Helsinki",
    "ash": "Ashburn", "hil": "Hillsboro", "sin": "Singapore",
}
# 24x24 stroke glyphs.
GLYPHS = {
    "server": '<rect x="4" y="4" width="16" height="6" rx="1.5"/><rect x="4" y="14" width="16" height="6" rx="1.5"/><path d="M7.5 7h.01M7.5 17h.01"/>',
    "database": '<ellipse cx="12" cy="5.5" rx="7" ry="2.5"/><path d="M5 5.5v13c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5v-13M5 12c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5"/>',
    "shield": '<path d="M12 3l7 2.8v5.4c0 4.4-3 8.3-7 9.8-4-1.5-7-5.4-7-9.8V5.8z"/><path d="M9.5 12l1.8 1.8 3.4-3.6"/>',
    "globe": '<circle cx="12" cy="12" r="8"/><path d="M4 12h16M12 4c2.2 2.3 3.2 5 3.2 8s-1 5.7-3.2 8c-2.2-2.3-3.2-5-3.2-8s1-5.7 3.2-8"/>',
    "cloud": '<path d="M7 18h10.5a4 4 0 0 0 .6-7.95A5.5 5.5 0 0 0 7.3 9.2 4.4 4.4 0 0 0 7 18z"/>',
    "mesh": '<circle cx="6" cy="6" r="1.6"/><circle cx="12" cy="6" r="1.6"/><circle cx="18" cy="6" r="1.6"/><circle cx="6" cy="12" r="1.6"/><circle cx="12" cy="12" r="1.6"/><circle cx="18" cy="12" r="1.6"/><circle cx="12" cy="18" r="1.6"/>',
    "list": '<path d="M8 7h11M8 12h11M8 17h11M4.5 7h.01M4.5 12h.01M4.5 17h.01"/>',
    "archive": '<rect x="3.5" y="4" width="17" height="5" rx="1"/><path d="M5 9v10h14V9M10 13h4"/>',
}
SOURCE_STYLE = {
    "world": ("globe", "Internet", "any address"),
    "cloudflare": ("cloud", "Cloudflare", "proxy ranges only"),
    "allowlist": ("list", "Allow-list", "specific public addresses"),
    "tailscale": ("mesh", "Tailscale", "tailnet · admin + WireGuard"),
}
EXPOSURE_PILL = {"critical": "EXPOSED", "public": "PUBLIC", "proxied": "VIA CF"}


def _icon(add: Any, x: float, y: float, glyph: str, color: str, size: int = 34) -> None:
    add(f'<rect x="{x}" y="{y}" width="{size}" height="{size}" rx="7" fill="{color}"/>')
    scale = (size - 10) / 24
    add(
        f'<g transform="translate({x + 5} {y + 5}) scale({scale:.3f})" fill="none" stroke="#fff" '
        f'stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">{GLYPHS[glyph]}</g>'
    )


def render_svg(topology: dict[str, Any], title: str = "Hetzner Cloud architecture", theme: str = "light") -> str:
    c = THEMES[theme]
    node_w, node_h, gap, pad = 204, 58, 12, 14
    margin, source_w, lane_h = 28, 196, 16
    servers: list[dict[str, Any]] = topology["servers"]
    boxes: list[dict[str, Any]] = topology.get("storage_boxes", [])
    stats: dict[str, int] = topology.get("stats", {})
    in_net = [item for item in servers if item["networks"]]
    outside = [item for item in servers if not item["networks"]]

    edge_targets = {
        item["name"]
        for item in servers
        if any(port != "icmp" for kind in ("world", "cloudflare", "allowlist") for port in item["ingress"].get(kind, []))
    }

    # Columns = locations (like availability zones), widest first.
    counts: dict[str, int] = {}
    for item in servers:
        counts[item["location"] or "?"] = counts.get(item["location"] or "?", 0) + 1
    for box in boxes:
        counts.setdefault(box["location"] or "?", 0)
    locations = sorted(counts, key=lambda key: (-counts[key], key))
    tiers = [key for key, _t, _w in GROUPS] + ["other"]

    def cell(members: list[dict[str, Any]], location: str, tier: str | None) -> list[dict[str, Any]]:
        chosen = [
            item for item in members
            if (item["location"] or "?") == location and (tier is None or item["group"] == tier)
        ]
        # Nodes with public ingress go first, so their routing lane sits above the cell.
        return sorted(chosen, key=lambda item: (item["name"] not in edge_targets, item["name"]))

    sub = {
        loc: max(1, min(3, max((len(cell(in_net, loc, tier)) for tier in tiers), default=1)))
        for loc in locations
    }
    public_kinds = ("world", "cloudflare", "allowlist")
    edges = [
        (kind, item["name"], [port for port in item["ingress"][kind] if port != "icmp"])
        for item in servers
        for kind in public_kinds
        if any(port != "icmp" for port in item["ingress"].get(kind, []))
    ]

    # --- horizontal geometry
    zone_x = margin + source_w + 64
    label_w = 118
    grid_x = zone_x + 16 + 16 + label_w
    col_x: dict[str, float] = {}
    x = grid_x
    for loc in locations:
        col_x[loc] = x
        x += sub[loc] * node_w + (sub[loc] - 1) * gap + 2 * pad + gap
    grid_right = x - gap
    width = grid_right + 16 + 16 + margin

    # --- vertical geometry
    header_h = 176
    zone_y = margin + header_h
    vpc_y = zone_y + 40
    y: float = vpc_y + 62  # VPC title, subnet strip, location headers
    positions: dict[str, tuple[float, float]] = {}
    bands: list[tuple[str, float, float]] = []
    node_tops: dict[float, float] = {}  # band start -> first node row

    def place(members: list[dict[str, Any]], top: float, tier: str | None) -> float:
        rows_needed = 0
        for loc in locations:
            members_here = cell(members, loc, tier)
            rows_needed = max(rows_needed, math.ceil(len(members_here) / sub[loc]) if members_here else 0)
        names = {item["name"] for item in members if tier is None or item["group"] == tier}
        lanes = sum(1 for _k, name, _p in edges if name in names)
        start = top
        top += lanes * lane_h + (10 if lanes else 0) + 10
        node_tops[start] = top
        for loc in locations:
            for index, item in enumerate(cell(members, loc, tier)):
                row, column = divmod(index, sub[loc])
                positions[item["name"]] = (col_x[loc] + pad + column * (node_w + gap), top + row * (node_h + gap))
        return top + rows_needed * (node_h + gap) + 4

    for tier in tiers:
        if not any(item["group"] == tier for item in in_net):
            continue
        start = y
        y = place(in_net, y, tier)
        bands.append((tier, start, y))
    vpc_bottom = y + 10
    outside_y = vpc_bottom + 24
    y = outside_y + 36
    storage_positions: dict[str, tuple[float, float]] = {}
    if outside or boxes:
        y = place(outside, y, None)
        # Storage Boxes continue the location columns under any outside servers.
        for loc in locations:
            used = len(cell(outside, loc, None))
            for offset, box in enumerate(item for item in boxes if (item["location"] or "?") == loc):
                row, column = divmod(used + offset, sub[loc])
                row_top = outside_y + 36 + 20 + row * (node_h + gap)
                storage_positions[box["name"]] = (col_x[loc] + pad + column * (node_w + gap), row_top)
                y = max(y, row_top + node_h + gap + 4)
        outside_bottom = y + 6
    else:
        outside_bottom = vpc_bottom
    zone_bottom = outside_bottom + 16
    legend_y = zone_bottom + 22
    height = legend_y + 92 + margin

    out: list[str] = []
    add = out.append
    add(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" viewBox="0 0 {width:.0f} {height:.0f}" font-family="ui-sans-serif, -apple-system, Segoe UI, Helvetica, Arial, sans-serif">')
    add(f'<rect width="100%" height="100%" rx="16" fill="{c["bg"]}"/>')
    add('<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="context-stroke"/></marker>'
        '<filter id="shadow" x="-5%" y="-10%" width="110%" height="130%"><feDropShadow dx="0" dy="1" stdDeviation="1.5" flood-color="#000" flood-opacity="0.08"/></filter></defs>')

    # --- header: title + summary tiles
    add(f'<text x="{margin}" y="{margin + 20}" font-size="22" font-weight="700" fill="{c["text"]}">{escape(title)}</text>')
    zone_names = sorted({item.get("network_zone", "") for item in servers if item.get("network_zone")})
    subtitle = f"network zone {', '.join(zone_names) or 'unknown'} · read-only API evidence · public IPs omitted"
    if topology.get("collected_at"):
        subtitle += f" · collected {str(topology['collected_at'])[:16].replace('T', ' ')} UTC"
    add(f'<text x="{margin}" y="{margin + 44}" font-size="13" fill="{c["muted"]}">{escape(subtitle)}</text>')
    tiles = [
        ("Servers", f"{stats.get('servers', len(servers))}", f"{stats.get('locations', len(locations))} locations", c["text"]),
        ("Internet-exposed", f"{stats.get('internet_exposed', 0)}", "open to any address", c["critical"] if stats.get("internet_exposed") else c["vpc"]),
        ("Behind Cloudflare", f"{stats.get('cloudflare_fronted', 0)}", "web ports CF-only", c["cloudflare"]),
        ("Tailscale admin", f"{stats.get('tailscale_admin', 0)}", "admin ports on tailnet", c["tailscale"]),
        ("Broad private ingress", f"{stats.get('broad_private_ingress', 0)}", "all TCP from the network", c["public"] if stats.get("broad_private_ingress") else c["vpc"]),
        ("Volumes", f"{stats.get('volumes', 0)}", f"{stats.get('volume_gb', 0):,} GB · {stats.get('unattached_volumes', 0)} unattached", c["text"]),
        ("Delete-protected", f"{stats.get('delete_protected', 0)}/{stats.get('servers', len(servers))}", f"{stats.get('deprecated_types', 0)} on deprecated types", c["public"] if stats.get("delete_protected", 0) < stats.get("servers", 0) else c["vpc"]),
    ]
    tile_gap = 12
    tile_w = (width - 2 * margin - tile_gap * (len(tiles) - 1)) / len(tiles)
    for index, (label, value, note, color) in enumerate(tiles):
        tx = margin + index * (tile_w + tile_gap)
        ty = margin + 66
        add(f'<rect x="{tx:.1f}" y="{ty}" width="{tile_w:.1f}" height="86" rx="10" fill="{c["surface"]}" stroke="{c["line"]}" filter="url(#shadow)"/>')
        add(f'<text x="{tx + 14:.1f}" y="{ty + 22}" font-size="11" font-weight="700" letter-spacing="0.6" fill="{c["muted"]}">{escape(label.upper())}</text>')
        add(f'<text x="{tx + 14:.1f}" y="{ty + 54}" font-size="28" font-weight="800" fill="{color}">{escape(value)}</text>')
        add(f'<text x="{tx + 14:.1f}" y="{ty + 74}" font-size="11.5" fill="{c["muted"]}">{escape(note)}</text>')

    # --- zone boundary
    add(f'<rect x="{zone_x}" y="{zone_y}" width="{width - zone_x - margin}" height="{zone_bottom - zone_y}" rx="12" fill="none" stroke="{c["zone"]}" stroke-width="1.4"/>')
    _icon(add, zone_x, zone_y, "cloud", "#d50c2d", 30)
    add(f'<text x="{zone_x + 40}" y="{zone_y + 20}" font-size="13" font-weight="700" fill="{c["text"]}">Hetzner Cloud project · network zone {escape(", ".join(zone_names) or "unknown")}</text>')

    # --- VPC (private network) boundary
    vpc_x = zone_x + 16
    vpc_w = width - margin - 16 - vpc_x
    network: dict[str, Any] = topology["networks"][0] if topology["networks"] else {"name": "private network", "ip_range": "", "subnets": []}
    add(f'<rect x="{vpc_x}" y="{vpc_y}" width="{vpc_w}" height="{vpc_bottom - vpc_y}" rx="10" fill="{c["vpc_fill"]}" stroke="{c["vpc"]}" stroke-width="1.6"/>')
    add(f'<rect x="{vpc_x}" y="{vpc_y}" width="26" height="26" rx="6" fill="{c["vpc"]}"/>')
    add(f'<g transform="translate({vpc_x + 5} {vpc_y + 5}) scale(0.67)" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round"><rect x="4" y="9" width="16" height="11" rx="2"/><path d="M8 9V6.5a4 4 0 0 1 8 0V9"/></g>')
    extra_nets = f" (+{len(topology['networks']) - 1} more)" if len(topology["networks"]) > 1 else ""
    add(f'<text x="{vpc_x + 36}" y="{vpc_y + 18}" font-size="13" font-weight="700" fill="{c["vpc"]}">Private network {escape(network["name"])} · {escape(network.get("ip_range", ""))}{escape(extra_nets)}</text>')
    subnets = ", ".join(network.get("subnets", [])) or "no subnets reported"
    add(f'<text x="{vpc_x + 36}" y="{vpc_y + 36}" font-size="11.5" fill="{c["muted"]}">subnet {escape(subnets)} · cloud firewalls attached per server</text>')

    # --- location columns (dashed, AZ-like) spanning VPC and outside band
    for loc in locations:
        lx = col_x[loc]
        lw = sub[loc] * node_w + (sub[loc] - 1) * gap + 2 * pad
        add(f'<rect x="{lx}" y="{vpc_y + 44}" width="{lw}" height="{outside_bottom - vpc_y - 50}" rx="8" fill="none" stroke="{c["location"]}" stroke-width="1.2" stroke-dasharray="6 5" opacity="0.8"/>')
        add(f'<text x="{lx + 10}" y="{vpc_y + 60}" font-size="11.5" font-weight="700" fill="{c["location"]}">{escape(loc.upper())} · {escape(LOCATION_NAMES.get(loc, "location"))} · {counts[loc]} server{"s" if counts[loc] != 1 else ""}</text>')

    # --- tier bands with labels
    for tier, top, bottom in bands:
        add(f'<rect x="{vpc_x + 8}" y="{top}" width="{label_w}" height="{bottom - top}" rx="6" fill="{c["band"]}"/>')
        color, glyph = CATEGORY.get(tier, CATEGORY["other"])
        label_top = node_tops.get(top, top)
        _icon(add, vpc_x + 16, label_top + 4, glyph, color, 22)
        label = next((title for key, title, _w in GROUPS if key == tier), "Other")
        for line_index, word in enumerate(label.replace(" & ", " &\n").split("\n")):
            add(f'<text x="{vpc_x + 16}" y="{label_top + 44 + line_index * 14}" font-size="11" font-weight="700" letter-spacing="0.4" fill="{c["muted"]}">{escape(word.strip().upper())}</text>')

    # --- outside band
    if outside or boxes:
        add(f'<rect x="{vpc_x}" y="{outside_y}" width="{vpc_w}" height="{outside_bottom - outside_y}" rx="10" fill="none" stroke="{c["line"]}" stroke-width="1.4" stroke-dasharray="3 4"/>')
        add(f'<text x="{vpc_x + 12}" y="{outside_y + 20}" font-size="12" font-weight="700" fill="{c["muted"]}">OUTSIDE THE PRIVATE NETWORK · public interface + cloud firewall only</text>')

    # --- trust sources
    kinds = [kind for kind in ("world", "cloudflare", "allowlist", "tailscale") if any(kind in item["ingress"] for item in servers)]
    source_pos: dict[str, tuple[float, float]] = {}
    sy = zone_y + 20.0
    for kind in kinds:
        glyph, name, note = SOURCE_STYLE[kind]
        add(f'<rect x="{margin}" y="{sy}" width="{source_w}" height="60" rx="12" fill="{c["surface"]}" stroke="{c[kind]}" stroke-width="1.6" filter="url(#shadow)"/>')
        _icon(add, margin + 12, sy + 13, glyph, c[kind], 34)
        add(f'<text x="{margin + 56}" y="{sy + 27}" font-size="14" font-weight="700" fill="{c["text"]}">{escape(name)}</text>')
        add(f'<text x="{margin + 56}" y="{sy + 44}" font-size="11" fill="{c["muted"]}">{escape(note)}</text>')
        source_pos[kind] = (margin + source_w, sy + 30)
        sy += 84
    if "tailscale" in source_pos:
        ts_x, ts_y = source_pos["tailscale"]
        reached = sum(1 for item in servers if "tailscale" in item["ingress"])
        add(f'<path d="M {ts_x} {ts_y} L {vpc_x - 2} {ts_y}" stroke="{c["tailscale"]}" stroke-width="2" stroke-dasharray="6 5" fill="none" marker-end="url(#arrow)"/>')
        add(f'<text x="{margin + source_w / 2}" y="{ts_y + 44}" text-anchor="middle" font-size="11" fill="{c["tailscale"]}">reaches {reached} servers</text>')

    # --- public edges: source → gutter → lane above the node row → down into the node
    gutters = {kind: zone_x - 30 + index * 7 for index, kind in enumerate(public_kinds)}
    lane_used: dict[float, int] = {}
    for kind, name, ports in edges:
        if name not in positions or kind not in source_pos:
            continue
        nx, ny = positions[name]
        sx, sy2 = source_pos[kind]
        used = lane_used.get(ny, 0)
        lane_used[ny] = used + 1
        lane_y = ny - 12 - used * lane_h
        target_x = nx + node_w - 26 - used * 10
        color = c[kind]
        add(f'<path d="M {sx} {sy2} L {gutters[kind]} {sy2} L {gutters[kind]} {lane_y} L {target_x} {lane_y} L {target_x} {ny}" stroke="{color}" stroke-width="{2.4 if kind == "world" else 1.8}" fill="none" stroke-linejoin="round" marker-end="url(#arrow)"/>')
        add(f'<text x="{target_x - 8}" y="{lane_y - 4}" text-anchor="end" font-size="10.5" font-weight="700" fill="{color}">{escape(", ".join(ports))}</text>')

    # --- nodes
    def node(x0: float, y0: float, name: str, detail: str, category: str, pill: tuple[str, str] | None, flags: list[tuple[str, str]]) -> None:
        color, glyph = CATEGORY.get(category, CATEGORY["other"])
        add(f'<rect x="{x0}" y="{y0}" width="{node_w}" height="{node_h}" rx="9" fill="{c["surface"]}" stroke="{c["line"]}" filter="url(#shadow)"/>')
        _icon(add, x0 + 10, y0 + 12, glyph, color, 34)
        add(f'<text x="{x0 + 54}" y="{y0 + 23}" font-size="13" font-weight="700" fill="{c["text"]}">{escape(name[:22])}</text>')
        add(f'<text x="{x0 + 54}" y="{y0 + 39}" font-size="11" fill="{c["muted"]}">{escape(detail[:28])}</text>')
        flag_x = x0 + 54
        for text, flag_color in flags[:2]:
            add(f'<text x="{flag_x}" y="{y0 + 52}" font-size="10" font-weight="700" fill="{flag_color}">{escape(text)}</text>')
            flag_x += 8 + len(text) * 6
        if pill:
            text, pill_color = pill
            pw = 8 + len(text) * 6.4
            add(f'<rect x="{x0 + node_w - pw - 8}" y="{y0 - 8}" width="{pw:.1f}" height="16" rx="8" fill="{pill_color}"/>')
            add(f'<text x="{x0 + node_w - pw / 2 - 8:.1f}" y="{y0 + 3.5}" text-anchor="middle" font-size="9.5" font-weight="800" letter-spacing="0.4" fill="#fff">{escape(text)}</text>')

    for item in servers:
        if item["name"] not in positions:
            continue
        nx, ny = positions[item["name"]]
        detail = " · ".join(part for part in (item["role"], item["type"]) if part)
        flags: list[tuple[str, str]] = []
        if item["volume_gb"]:
            flags.append((f"{item['volume_gb']} GB", c["muted"]))
        if item["deprecated_type"]:
            flags.append(("deprecated type", c["public"]))
        if item["delete_protection"]:
            flags.append(("protected", c["vpc"]))
        if not item["firewall"] and item["public_ip"]:
            flags.insert(0, ("no firewall", c["critical"]))
        pill = (EXPOSURE_PILL[item["exposure"]], c[item["exposure"]]) if item["exposure"] in EXPOSURE_PILL else None
        node(nx, ny, item["name"], detail, "security" if item["sensitive"] and item["group"] == "security" else ("data" if item["sensitive"] else item["group"]), pill, flags)
    for box in boxes:
        if box["name"] in storage_positions:
            bx, by = storage_positions[box["name"]]
            node(bx, by, box["name"], f"Storage Box · {box['type']}", "storage", None, [])

    # --- legend
    add(f'<rect x="{margin}" y="{legend_y}" width="{width - 2 * margin}" height="92" rx="10" fill="{c["surface"]}" stroke="{c["line"]}"/>')
    add(f'<text x="{margin + 16}" y="{legend_y + 22}" font-size="11" font-weight="700" letter-spacing="0.6" fill="{c["muted"]}">LEGEND</text>')
    lx = margin + 16.0
    for key, label in (("edge", "Edge & web"), ("app", "Application"), ("data", "Data"), ("security", "Identity & secrets"), ("other", "Other"), ("storage", "Storage Box")):
        color, glyph = CATEGORY[key]
        _icon(add, lx, legend_y + 36, glyph, color, 22)
        add(f'<text x="{lx + 28}" y="{legend_y + 51}" font-size="11.5" fill="{c["text"]}">{escape(label)}</text>')
        lx += 36 + len(label) * 6.6 + 14
    lx = margin + 16.0
    line_y = legend_y + 76
    for kind, label, dash in (("world", "Internet ingress", ""), ("cloudflare", "Cloudflare-only ingress", ""), ("tailscale", "Tailscale admin", "6 5")):
        add(f'<path d="M {lx} {line_y} L {lx + 34} {line_y}" stroke="{c[kind]}" stroke-width="2.2" stroke-dasharray="{dash}" marker-end="url(#arrow)"/>')
        add(f'<text x="{lx + 42}" y="{line_y + 4}" font-size="11.5" fill="{c["text"]}">{escape(label)}</text>')
        lx += 60 + len(label) * 6.4 + 18
    for key in ("critical", "public", "proxied"):
        text = EXPOSURE_PILL[key]
        pw = 8 + len(text) * 6.4
        add(f'<rect x="{lx}" y="{line_y - 8}" width="{pw:.1f}" height="16" rx="8" fill="{c[key]}"/>')
        add(f'<text x="{lx + pw / 2:.1f}" y="{line_y + 3.5}" text-anchor="middle" font-size="9.5" font-weight="800" fill="#fff">{escape(text)}</text>')
        lx += pw + 10
    add(f'<text x="{lx + 4}" y="{line_y + 4}" font-size="11.5" fill="{c["muted"]}">no pill = no public ingress besides WireGuard/ICMP</text>')
    add(f'<rect x="{width - margin - 330}" y="{legend_y + 64}" width="22" height="14" rx="3" fill="none" stroke="{c["location"]}" stroke-dasharray="4 3"/>')
    add(f'<text x="{width - margin - 300}" y="{legend_y + 76}" font-size="11.5" fill="{c["text"]}">location</text>')
    add(f'<rect x="{width - margin - 236}" y="{legend_y + 64}" width="22" height="14" rx="3" fill="{c["vpc_fill"]}" stroke="{c["vpc"]}"/>')
    add(f'<text x="{width - margin - 206}" y="{legend_y + 76}" font-size="11.5" fill="{c["text"]}">private network (VPC)</text>')
    add("</svg>")
    return "\n".join(out)
