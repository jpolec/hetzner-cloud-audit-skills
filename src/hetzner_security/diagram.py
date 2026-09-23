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

from .actions import cost_insights
from .topology import GROUPS

THEMES: dict[str, dict[str, str]] = {
    "light": {
        "bg": "#f4f4f4", "surface": "#ffffff", "line": "#e3e3e3", "text": "#1f1f1f", "muted": "#6b6b6b",
        "zone": "#8a8a8a", "vpc": "#1f9d55", "vpc_fill": "#f6fbf8", "location": "#2f6fdb", "band": "#fafafa",
        "critical": "#d50c2d", "public": "#d98e04", "proxied": "#f38020", "private": "#2f6fdb",
        "world": "#d50c2d", "edge": "#f38020", "mesh": "#6d4fc2", "allowlist": "#7a7a7a",
    },
    "dark": {
        "bg": "#0b1220", "surface": "#111f36", "line": "#23324d", "text": "#e5edf7", "muted": "#8aa0bd",
        "zone": "#8aa0bd", "vpc": "#34d399", "vpc_fill": "#0f1a2e", "location": "#60a5fa", "band": "#0f1a2e",
        "critical": "#f87171", "public": "#fde047", "proxied": "#fb923c", "private": "#60a5fa",
        "world": "#f87171", "edge": "#fb923c", "mesh": "#a78bfa", "allowlist": "#94a3b8",
    },
}
CATEGORY = {
    "edge": ("#7c4dff", "globe"),
    "app": ("#e8710a", "server"),
    "data": ("#2f6fdb", "database"),
    "security": ("#d50c2d", "shield"),
    "other": ("#6b7280", "server"),
    "storage": ("#0f8b8d", "archive"),
    "lb": ("#7c4dff", "balance"),
    "k8s": ("#326ce5", "wheel"),
    "dedicated": ("#374151", "server"),
    "vswitch": ("#6d4fc2", "mesh"),
    "bucket": ("#0f8b8d", "bucket"),
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
    "balance": '<circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="12" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v10M12 11l-6 6M12 11l6 6"/>',
    "wheel": '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="2"/><path d="M12 4v6M12 14v6M4 12h6M14 12h6M6.3 6.3l4.2 4.2M13.5 13.5l4.2 4.2M17.7 6.3l-4.2 4.2M10.5 13.5l-4.2 4.2"/>',
    "bucket": '<path d="M5 7h14l-1.6 12.2a2 2 0 0 1-2 1.8H8.6a2 2 0 0 1-2-1.8z"/><ellipse cx="12" cy="7" rx="7" ry="2.2"/>',
    "archive": '<rect x="3.5" y="4" width="17" height="5" rx="1"/><path d="M5 9v10h14V9M10 13h4"/>',
}
SOURCE_STYLE = {
    "world": ("globe", "Internet", "any address"),
    "edge": ("cloud", "Edge proxy", "CDN / WAF ranges only"),
    "allowlist": ("list", "Allow-list", "specific public addresses"),
    "mesh": ("mesh", "Mesh VPN", "Tailscale / NetBird · admin"),
}
EXPOSURE_PILL = {"critical": "EXPOSED", "public": "PUBLIC", "proxied": "VIA CDN"}
EDGE_SHORT = {"Cloudflare": "CF", "Fastly": "FASTLY", "Bunny CDN": "BUNNY", "AWS CloudFront": "CLOUDFRONT",
              "Gcore CDN": "GCORE", "Imperva": "IMPERVA"}


def _pill_text(item: dict[str, Any]) -> str:
    """Exposure pill; a proxied server names its edge provider when there is exactly one."""
    providers = item.get("edge_providers") or []
    if item["exposure"] == "proxied" and len(providers) == 1:
        return f"VIA {EDGE_SHORT.get(providers[0], 'CDN')}"
    return EXPOSURE_PILL[item["exposure"]]


def _edge_label(topology: dict[str, Any]) -> str:
    providers = topology.get("edge_providers") or []
    return ", ".join(providers) if providers else "Edge proxy"


def _icon(add: Any, x: float, y: float, glyph: str, color: str, size: int = 34) -> None:
    add(f'<rect x="{x}" y="{y}" width="{size}" height="{size}" rx="7" fill="{color}"/>')
    scale = (size - 10) / 24
    add(
        f'<g transform="translate({x + 5} {y + 5}) scale({scale:.3f})" fill="none" stroke="#fff" '
        f'stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">{GLYPHS[glyph]}</g>'
    )


HEADER_H = 206  # brand line, title, subtitle, and summary tiles


def _open_svg(add: Any, c: dict[str, str], width: float, height: float) -> None:
    add(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" viewBox="0 0 {width:.0f} {height:.0f}" font-family="ui-sans-serif, -apple-system, Segoe UI, Helvetica, Arial, sans-serif">')
    add(f'<rect width="100%" height="100%" rx="16" fill="{c["bg"]}"/>')
    add('<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="context-stroke"/></marker>'
        '<filter id="shadow" x="-5%" y="-10%" width="110%" height="130%"><feDropShadow dx="0" dy="1" stdDeviation="1.5" flood-color="#000" flood-opacity="0.08"/></filter></defs>')


def _header(
    add: Any, c: dict[str, str], width: float, margin: float, title: str, subtitle: str,
    tiles: list[tuple[str, str, str, str]],
) -> None:
    """Brand line (tool name), title, subtitle, and one row of summary tiles."""
    add(f'<rect x="{margin}" y="{margin}" width="22" height="22" rx="5" fill="#d50c2d"/>')
    add(f'<g transform="translate({margin + 4} {margin + 4}) scale(0.58)" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">{GLYPHS["shield"]}</g>')
    add(f'<text x="{margin + 30}" y="{margin + 16}" font-size="14" font-weight="800" fill="{c["text"]}">hetzner-audit</text>')
    add(f'<text x="{margin + 132}" y="{margin + 16}" font-size="12.5" fill="{c["muted"]}">read-only Hetzner Cloud audit · github.com/jpolec/hetzner-cloud-audit-skills</text>')
    add(f'<text x="{margin}" y="{margin + 50}" font-size="22" font-weight="700" fill="{c["text"]}">{escape(title)}</text>')
    add(f'<text x="{margin}" y="{margin + 74}" font-size="13" fill="{c["muted"]}">{escape(subtitle)}</text>')
    tile_gap = 12
    tile_w = (width - 2 * margin - tile_gap * (len(tiles) - 1)) / len(tiles)
    for index, (label, value, note, color) in enumerate(tiles):
        tx = margin + index * (tile_w + tile_gap)
        ty = margin + 96
        add(f'<rect x="{tx:.1f}" y="{ty}" width="{tile_w:.1f}" height="86" rx="10" fill="{c["surface"]}" stroke="{c["line"]}" filter="url(#shadow)"/>')
        add(f'<text x="{tx + 14:.1f}" y="{ty + 22}" font-size="11" font-weight="700" letter-spacing="0.6" fill="{c["muted"]}">{escape(label.upper())}</text>')
        add(f'<text x="{tx + 14:.1f}" y="{ty + 54}" font-size="28" font-weight="800" fill="{color}">{escape(value)}</text>')
        add(f'<text x="{tx + 14:.1f}" y="{ty + 74}" font-size="11.5" fill="{c["muted"]}">{escape(note)}</text>')


ACTION_ROW_H = 46
LEVEL_COLOR = {"HIGH": "vpc", "MEDIUM": "public", "LOW": "muted"}


def _actions_height(actions: list[dict[str, Any]] | None, limit: int) -> float:
    return 0 if not actions else 44 + min(len(actions), limit) * ACTION_ROW_H + 12


def _actions_panel(
    add: Any, c: dict[str, str], x: float, y: float, width: float, actions: list[dict[str, Any]],
    limit: int, currency: str = "EUR", title: str = "RECOMMENDED ACTIONS",
) -> None:
    """Ranked next steps: title, saving, evidence level, risk, and the concrete next step."""
    height = _actions_height(actions, limit)
    add(f'<rect x="{x}" y="{y}" width="{width}" height="{height - 12}" rx="10" fill="{c["surface"]}" stroke="{c["line"]}" filter="url(#shadow)"/>')
    add(f'<text x="{x + 16}" y="{y + 24}" font-size="11" font-weight="700" letter-spacing="0.6" fill="{c["muted"]}">{escape(title)}</text>')
    add(f'<text x="{x + width - 16}" y="{y + 24}" text-anchor="end" font-size="11" fill="{c["muted"]}">plans for a human · the tool changes nothing</text>')
    for index, item in enumerate(actions[:limit]):
        row_y = y + 40 + index * ACTION_ROW_H
        add(f'<circle cx="{x + 28}" cy="{row_y + 14}" r="11" fill="{c["text"]}"/>')
        add(f'<text x="{x + 28}" y="{row_y + 18}" text-anchor="middle" font-size="11" font-weight="800" fill="{c["surface"]}">{item["rank"]}</text>')
        add(f'<text x="{x + 48}" y="{row_y + 12}" font-size="12.5" font-weight="700" fill="{c["text"]}">{escape(_short(item["title"], 96))}</text>')
        add(f'<text x="{x + 48}" y="{row_y + 29}" font-size="11" fill="{c["muted"]}">{escape(_short(item["next_step"], 150))}</text>')
        saving = f"{currency} {item['saving_monthly']:.2f}/mo" if item.get("saving_monthly") else "saving TBD"
        level = item["evidence_level"]
        right = x + width - 16
        add(f'<text x="{right}" y="{row_y + 12}" text-anchor="end" font-size="11" font-weight="700" fill="{c["text"]}">{escape(saving)}  ·  risk {escape(item["risk"])}</text>')
        pill_w = 12 + len(level) * 7
        add(f'<rect x="{right - pill_w - 70}" y="{row_y + 18}" width="{pill_w}" height="15" rx="7.5" fill="{c[LEVEL_COLOR[level]]}"/>')
        add(f'<text x="{right - pill_w / 2 - 70}" y="{row_y + 29}" text-anchor="middle" font-size="9.5" font-weight="800" fill="#fff">{level}</text>')
        add(f'<text x="{right}" y="{row_y + 29}" text-anchor="end" font-size="10.5" fill="{c["muted"]}">evidence</text>')


def render_svg(
    topology: dict[str, Any], title: str = "Hetzner Cloud architecture", theme: str = "light",
    actions: list[dict[str, Any]] | None = None,
) -> str:
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
        if any(port != "icmp" for kind in ("world", "edge", "allowlist") for port in item["ingress"].get(kind, []))
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
    public_kinds = ("world", "edge", "allowlist")
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
    header_h = HEADER_H
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
    beyond = _beyond_sections(topology, c)
    beyond_y = zone_bottom + 22
    per_row = max(1, int((width - 2 * margin - 32 + gap) // (node_w + gap)))
    beyond_h = _beyond_height(beyond, per_row, node_h, gap)
    actions_y = beyond_y + beyond_h + (22 if beyond_h else 0)
    legend_y = actions_y + _actions_height(actions, 6)
    height = legend_y + 92 + margin

    out: list[str] = []
    add = out.append
    _open_svg(add, c, width, height)
    zone_names = sorted({item.get("network_zone", "") for item in servers if item.get("network_zone")})
    hosts = sum(1 for item in servers if item.get("host"))
    evidence = f"host evidence for {hosts} server{'s' if hosts != 1 else ''}" if hosts else "cloud control plane only (no host evidence)"
    subtitle = f"network zone {', '.join(zone_names) or 'unknown'} · {evidence} · public IPs omitted"
    if topology.get("collected_at"):
        subtitle += f" · collected {str(topology['collected_at'])[:16].replace('T', ' ')} UTC"
    _header(
        add, c, width, margin, title, subtitle,
        [
            ("Servers", f"{stats.get('servers', len(servers))}", f"{stats.get('locations', len(locations))} locations", c["text"]),
            ("Internet-exposed", f"{stats.get('internet_exposed', 0)}", "open to any address", c["critical"] if stats.get("internet_exposed") else c["vpc"]),
            ("Behind edge proxy", f"{stats.get('edge_fronted', 0)}", _short(_edge_label(topology), 30), c["edge"]),
            ("Mesh VPN admin", f"{stats.get('mesh_admin', 0)}", "admin ports on the mesh", c["mesh"]),
            ("No public ingress", f"{stats.get('no_public_ingress', 0)}", f"{stats.get('tunnels', 0)} with a tunnel agent seen", c["vpc"]),
            ("Private network", f"{stats.get('private_members', 0)}", "servers · not filtered by cloud FW", c["public"] if stats.get("private_members", 0) > 1 else c["vpc"]),
            ("Volumes", f"{stats.get('volumes', 0)}", f"{stats.get('volume_gb', 0):,} GB · {stats.get('unattached_volumes', 0)} unattached", c["text"]),
            ("Delete-protected", f"{stats.get('delete_protected', 0)}/{stats.get('servers', len(servers))}", "servers protected from deletion", c["public"] if stats.get("delete_protected", 0) < stats.get("servers", 0) else c["vpc"]),
        ],
    )

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
    add(f'<text x="{vpc_x + 36}" y="{vpc_y + 36}" font-size="11.5" fill="{c["muted"]}">subnet {escape(subnets)} · any-to-any on all ports: Hetzner Cloud Firewalls do not filter private networks</text>')

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
    kinds = [kind for kind in ("world", "edge", "allowlist", "mesh") if any(kind in item["ingress"] for item in servers)]
    source_pos: dict[str, tuple[float, float]] = {}
    sy = zone_y + 20.0
    for kind in kinds:
        glyph, name, note = SOURCE_STYLE[kind]
        if kind == "edge":
            name = _short(_edge_label(topology), 22)
        add(f'<rect x="{margin}" y="{sy}" width="{source_w}" height="60" rx="12" fill="{c["surface"]}" stroke="{c[kind]}" stroke-width="1.6" filter="url(#shadow)"/>')
        _icon(add, margin + 12, sy + 13, glyph, c[kind], 34)
        add(f'<text x="{margin + 56}" y="{sy + 27}" font-size="14" font-weight="700" fill="{c["text"]}">{escape(name)}</text>')
        add(f'<text x="{margin + 56}" y="{sy + 44}" font-size="11" fill="{c["muted"]}">{escape(note)}</text>')
        source_pos[kind] = (margin + source_w, sy + 30)
        sy += 84
    if "mesh" in source_pos:
        ts_x, ts_y = source_pos["mesh"]
        reached = sum(1 for item in servers if "mesh" in item["ingress"])
        add(f'<path d="M {ts_x} {ts_y} L {vpc_x - 2} {ts_y}" stroke="{c["mesh"]}" stroke-width="2" stroke-dasharray="6 5" fill="none" marker-end="url(#arrow)"/>')
        add(f'<text x="{margin + source_w / 2}" y="{ts_y + 44}" text-anchor="middle" font-size="11" fill="{c["mesh"]}">reaches {reached} servers</text>')

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
        for text, flag_color in flags[:3]:
            if flag_x + len(text) * 5.9 > x0 + node_w - 6:
                break  # never draw a clipped flag; the most important flags come first
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
        host = item.get("host")
        if host and host["docker_bypass"]:
            flags.insert(0, (f"docker bypass {len(host['docker_bypass'])}", c["critical"]))
        if host and host["firewall"] == "none":
            flags.insert(0, ("no host fw", c["public"]))
        elif host and host["firewall"] == "unknown":
            flags.insert(0, ("host fw unknown", c["muted"]))
        if item.get("k8s_role"):
            flags.insert(0, ("k8s cp" if item["k8s_role"] == "control-plane" else "k8s", c["location"]))
        if not item["firewall"] and item["public_ip"]:
            flags.insert(0, ("no firewall", c["critical"]))
        pill = (_pill_text(item), c[item["exposure"]]) if item["exposure"] in EXPOSURE_PILL else None
        if item.get("tunnels"):
            flags.insert(0, ("tunnel", c["vpc"]))
        node(nx, ny, item["name"], detail, "security" if item["sensitive"] and item["group"] == "security" else ("data" if item["sensitive"] else item["group"]), pill, flags)
    for box in boxes:
        if box["name"] in storage_positions:
            bx, by = storage_positions[box["name"]]
            node(bx, by, box["name"], f"Storage Box · {box['type']}", "storage", None, [])

    if beyond_h:
        _draw_beyond(add, c, margin, beyond_y, width - 2 * margin, beyond, per_row, node, node_w, node_h, gap)
    if actions:
        _actions_panel(add, c, margin, actions_y, width - 2 * margin, actions, 6)

    # --- legend
    add(f'<rect x="{margin}" y="{legend_y}" width="{width - 2 * margin}" height="92" rx="10" fill="{c["surface"]}" stroke="{c["line"]}"/>')
    add(f'<text x="{margin + 16}" y="{legend_y + 22}" font-size="11" font-weight="700" letter-spacing="0.6" fill="{c["muted"]}">LEGEND</text>')
    lx = margin + 16.0
    legend_items = [("edge", "Edge & web"), ("app", "Application"), ("data", "Data"), ("security", "Identity & secrets"), ("other", "Other"), ("storage", "Storage Box")]
    present = {card[2] for _title, cards in beyond for card in cards}
    legend_items += [(key, label) for key, label in (("lb", "Load balancer"), ("k8s", "Kubernetes"), ("dedicated", "Dedicated"),
                                                     ("vswitch", "vSwitch"), ("bucket", "Bucket")) if key in present]
    for key, label in legend_items:
        color, glyph = CATEGORY[key]
        _icon(add, lx, legend_y + 36, glyph, color, 22)
        add(f'<text x="{lx + 28}" y="{legend_y + 51}" font-size="11.5" fill="{c["text"]}">{escape(label)}</text>')
        lx += 36 + len(label) * 6.6 + 14
    lx = margin + 16.0
    line_y = legend_y + 76
    for kind, label, dash in (("world", "Internet ingress", ""), ("edge", "Edge-proxy-only ingress", ""), ("mesh", "Mesh VPN admin", "6 5")):
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


# ---------------------------------------------------------------- per-VM connectivity view

Card = tuple[str, str, str, tuple[str, str] | None, list[tuple[str, str]]]  # name, detail, category, pill, flags


def _beyond_sections(topology: dict[str, Any], c: dict[str, str]) -> list[tuple[str, list[Card]]]:
    """Cards for everything outside the server grid, grouped by source."""
    sections: list[tuple[str, list[Card]]] = []
    lbs: list[Card] = [
        (item["name"], ", ".join(item["services"]) or "no services", "lb",
         ("PUBLIC", c["public"]) if item["public"] else None,
         [(f"→ {', '.join(item['targets'][:3])}" if item["targets"] else "no targets", c["muted"])])
        for item in topology.get("load_balancers") or []
    ]
    if lbs:
        sections.append(("LOAD BALANCERS · Hetzner Cloud", lbs))
    k8s = topology.get("kubernetes")
    if k8s:
        flags = [(f"{k8s['risky_workloads']} risky", c["critical"] if k8s["risky_workloads"] else c["vpc"]),
                 (f"{k8s['node_port_services']} NodePort svc", c["public"] if k8s["node_port_services"] else c["muted"])]
        sections.append(("KUBERNETES · correlated from kubectl", [
            (k8s["name"], f"{len(k8s['nodes'])} nodes: {', '.join(k8s['nodes'][:3])}", "k8s", None, flags),
            *[(name, "integration detected", "k8s", None, []) for name in k8s["integrations"][:3]],
        ]))
    robot: list[Card] = [
        (item["name"], f"{item['product'] or ''} · {item['dc'] or ''}", "dedicated",
         ("NO FW", c["critical"]) if item["firewall"] != "active" else None,
         [("Robot fw " + item["firewall"], c["vpc"] if item["firewall"] == "active" else c["critical"])]
         + ([("IPv6 open", c["public"])] if item["firewall"] == "active" and not item["filter_ipv6"] else []))
        for item in topology.get("robot_servers") or []
    ]
    robot += [
        (item["name"], f"vSwitch · VLAN {item['vlan']}", "vswitch", ("HYBRID", c["mesh"]) if item["cloud_networks"] else None,
         [(f"{len(item['members'])} dedicated ↔ {', '.join(item['cloud_networks']) or 'no cloud net'}", c["muted"])])
        for item in topology.get("vswitches") or []
    ]
    if robot:
        sections.append(("DEDICATED SERVERS · Hetzner Robot", robot))
    buckets: list[Card] = [
        (item["name"], f"bucket · {item['location']}", "bucket", ("PUBLIC", c["critical"]) if item["public"] else None,
         [("versioned", c["vpc"]) if item["versioning"] else ("no versioning", c["public"])])
        for item in topology.get("buckets") or []
    ]
    if buckets:
        sections.append(("OBJECT STORAGE · S3 API", buckets))
    return sections


def _beyond_height(sections: list[tuple[str, list[Card]]], per_row: int, node_h: float, gap: float) -> float:
    if not sections:
        return 0
    rows = sum(math.ceil(len(cards) / per_row) for _title, cards in sections)
    return 40 + len(sections) * 34 + rows * (node_h + gap + 6) + 8


def _draw_beyond(
    add: Any, c: dict[str, str], x: float, y: float, width: float, sections: list[tuple[str, list[Card]]],
    per_row: int, node: Any, node_w: float, node_h: float, gap: float,
) -> None:
    height = _beyond_height(sections, per_row, node_h, gap)
    add(f'<rect x="{x}" y="{y}" width="{width}" height="{height}" rx="12" fill="none" stroke="{c["zone"]}" stroke-width="1.2" stroke-dasharray="2 4"/>')
    add(f'<text x="{x + 16}" y="{y + 24}" font-size="12" font-weight="700" fill="{c["muted"]}">BEYOND THE SERVER GRID · load balancers, Kubernetes, dedicated servers, Object Storage</text>')
    top = y + 40
    for title, cards in sections:
        add(f'<text x="{x + 16}" y="{top + 16}" font-size="11" font-weight="700" letter-spacing="0.5" fill="{c["text"]}">{escape(title)}</text>')
        top += 34
        for index, (name, detail, category, pill, flags) in enumerate(cards):
            row, column = divmod(index, per_row)
            node(x + 16 + column * (node_w + gap), top + row * (node_h + gap + 6), name, detail, category, pill, flags)
        top += math.ceil(len(cards) / per_row) * (node_h + gap + 6)


def _chips(item: dict[str, Any]) -> list[tuple[str, str]]:
    """Ingress summary per trust class, as (text, theme key) chips."""
    chips: list[tuple[str, str]] = []
    labels = {"world": "Internet", "edge": ", ".join(item.get("edge_providers") or []) or "edge proxy", "allowlist": "allow-list"}
    for kind in ("world", "edge", "allowlist"):
        ports = [port.split("/")[-1] if port.startswith("tcp/") else port for port in item["ingress"].get(kind, []) if port != "icmp"]
        if ports:
            chips.append((f"{labels[kind]} {','.join(ports)}", kind))
    admin = [
        port.split("/")[-1] if port.startswith("tcp/") else port
        for port in item["ingress"].get("mesh", [])
        if port.startswith("tcp/")
    ]
    if admin:
        chips.append((f"mesh VPN {','.join(admin)}", "mesh"))
    return chips


def _vm_card(
    add: Any, c: dict[str, str], x: float, y: float, w: float, h: float, item: dict[str, Any],
    lines: list[tuple[str, str]], category: str,
) -> None:
    color, glyph = CATEGORY.get(category, CATEGORY["other"])
    add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="9" fill="{c["surface"]}" stroke="{c["line"]}" filter="url(#shadow)"/>')
    _icon(add, x + 10, y + 12, glyph, color, 34)
    add(f'<text x="{x + 54}" y="{y + 24}" font-size="13" font-weight="700" fill="{c["text"]}">{escape(item["name"][:24])}</text>')
    for index, (text, color_key) in enumerate(lines):
        weight = "700" if color_key not in {"muted", "text"} else "400"
        add(f'<text x="{x + 54}" y="{y + 40 + index * 14}" font-size="10.5" font-weight="{weight}" fill="{c[color_key]}">{escape(text[:34])}</text>')
    if item["exposure"] in EXPOSURE_PILL:
        text = _pill_text(item)
        pw = 8 + len(text) * 6.4
        add(f'<rect x="{x + w - pw - 8}" y="{y - 8}" width="{pw:.1f}" height="16" rx="8" fill="{c[item["exposure"]]}"/>')
        add(f'<text x="{x + w - pw / 2 - 8:.1f}" y="{y + 3.5}" text-anchor="middle" font-size="9.5" font-weight="800" fill="#fff">{escape(text)}</text>')


def _category(item: dict[str, Any]) -> str:
    if item["sensitive"]:
        return "security" if item["group"] == "security" else "data"
    return str(item["group"])


def _high_value(item: dict[str, Any]) -> bool:
    """Databases, identity, and secrets hosts, plus data-role hosts that face the Internet or an edge proxy."""
    return bool(item["sensitive"]) or (item["group"] == "data" and item["exposure"] in {"public", "critical", "proxied"})


def render_connectivity_svg(
    topology: dict[str, Any], title: str = "Per-VM connectivity", theme: str = "light",
    actions: list[dict[str, Any]] | None = None,
) -> str:
    """Bus view of the private network: entry points, high-value hosts, and the blast radius between them."""
    c = THEMES[theme]
    margin, card_w, card_h, gap, per_row = 28, 232, 84, 16, 6
    servers: list[dict[str, Any]] = topology["servers"]
    in_net = [item for item in servers if item["networks"]]
    outside = [item for item in servers if not item["networks"]]
    high_value = [item for item in in_net if _high_value(item)]
    entry = [item for item in in_net if item["exposure"] in {"public", "critical", "proxied"}]
    # Quiet members first, entry points in the row(s) right above the bus, high-value hosts below it.
    quiet = sorted((item for item in in_net if not _high_value(item) and item not in entry), key=lambda item: item["name"])
    entry_up = sorted((item for item in entry if not _high_value(item)), key=lambda item: item["name"])
    upper = quiet + entry_up
    lower = sorted(high_value, key=lambda item: item["name"])
    width = margin * 2 + per_row * card_w + (per_row - 1) * gap
    rows_up = max(1, math.ceil(len(quiet) / per_row) + math.ceil(len(entry_up) / per_row))
    rows_down = max(1, math.ceil(len(lower) / per_row)) if lower else 0
    top = margin + HEADER_H + 34
    bus_y = top + rows_up * (card_h + gap * 2) + 30
    lower_top = bus_y + 76
    outside_top = lower_top + rows_down * (card_h + gap * 2) + (40 if outside else 0)
    actions_y = outside_top + (math.ceil(len(outside) / per_row) * (card_h + gap * 2) + 30 if outside else 0) + 10
    security_actions = [item for item in actions or [] if item.get("category") == "security"]
    legend_y = actions_y + _actions_height(security_actions, 4)
    height = legend_y + 70 + margin

    out: list[str] = []
    add = out.append
    _open_svg(add, c, width, height)
    network = topology["networks"][0] if topology["networks"] else {"name": "private network", "ip_range": ""}
    stats = topology.get("stats", {})
    roles = sorted({item["role"] or item["group"] for item in high_value})
    _header(
        add, c, width, margin, title,
        "blast radius on the private network · cloud control plane only (host firewalls not observed) · public IPs omitted",
        [
            ("In private network", str(len(in_net)), f"{network['name']} · {network.get('ip_range', '')}", c["vpc"]),
            ("Reachable pairs", f"{len(in_net) * max(len(in_net) - 1, 0)}", "any-to-any, every port", c["public"] if len(in_net) > 1 else c["vpc"]),
            ("High-value on shared L3", str(len(high_value)), _short(", ".join(roles) or "none", 34), c["critical"] if high_value else c["vpc"]),
            ("Entry points in network", str(len(entry)), "Internet or edge-proxy ingress", c["critical"] if entry else c["vpc"]),
            ("Outside network", str(len(outside)), "public interface + cloud FW only", c["text"]),
            ("Mesh VPN admin", str(stats.get("mesh_admin", 0)), "admin ports on the mesh", c["mesh"]),
        ],
    )

    positions: dict[str, tuple[float, float]] = {}
    entry_top = top + math.ceil(len(quiet) / per_row) * (card_h + gap * 2)
    for members, start_y in ((quiet, top), (entry_up, entry_top), (lower, lower_top + 6)):
        for index, item in enumerate(members):
            row, column = divmod(index, per_row)
            positions[item["name"]] = (margin + column * (card_w + gap), start_y + row * (card_h + gap * 2))

    # Bus and blast-radius statement.
    add(f'<rect x="{margin}" y="{bus_y}" width="{width - 2 * margin}" height="34" rx="17" fill="{c["vpc_fill"]}" stroke="{c["vpc"]}" stroke-width="2"/>')
    add(f'<text x="{margin + 18}" y="{bus_y + 22}" font-size="13" font-weight="700" fill="{c["vpc"]}">{escape(network["name"])} · {escape(network.get("ip_range", ""))} — any-to-any on every port: Hetzner Cloud Firewalls do not filter private networks</text>')
    if high_value:
        lines_blast = [
            f"Blast radius: any of the {len(in_net) - 1} other members, including {len(entry)} Internet/edge-proxy "
            f"entry point{'s' if len(entry) != 1 else ''}, has L3 access to {', '.join(item['name'] for item in high_value)} on every port.",
            "Cloud firewalls do not stop it; only host firewalls, localhost binds, and service authentication do (not observed by this audit).",
        ]
        # Next to the high-value cards when there is room, so the flow arrows never cross the text.
        free_columns = per_row - min(len(lower), per_row)
        if free_columns >= 2:
            text_x = margin + (per_row - free_columns) * (card_w + gap) + 8
            chars = int((free_columns * (card_w + gap) - 24) / 6.6)
            text_y = lower_top + 14
        else:
            text_x, chars, text_y = margin, 200, lower_top + rows_down * (card_h + gap * 2) - 6
        wrapped: list[tuple[str, int]] = []
        for index, text in enumerate(lines_blast):
            words, line = text.split(), ""
            for word in words:
                if len(line) + len(word) + 1 > chars:
                    wrapped.append((line, index))
                    line = word
                else:
                    line = f"{line} {word}".strip()
            wrapped.append((line, index))
        for row, (text, index) in enumerate(wrapped):
            add(f'<text x="{text_x}" y="{text_y + row * 17}" font-size="12" font-weight="{700 if index == 0 else 400}" fill="{c["critical"]}">{escape(text)}</text>')

    # Membership stubs; entry points flow into the bus and the bus flows into high-value hosts.
    for item in in_net:
        x, y = positions[item["name"]]
        link_x = x + card_w / 2
        if item in upper:
            hot = item in entry
            stroke, stroke_w, marker = (c["critical"], 2, ' marker-end="url(#arrow)"') if hot else (c["line"], 1.4, "")
            add(f'<path d="M {link_x} {y + card_h} L {link_x} {bus_y - 2}" stroke="{stroke}" stroke-width="{stroke_w}"{marker}/>')
        else:
            add(f'<path d="M {link_x} {bus_y + 36} L {link_x} {y - 2}" stroke="{c["critical"]}" stroke-width="2" marker-end="url(#arrow)"/>')

    add(f'<text x="{margin}" y="{top - 12}" font-size="11.5" font-weight="700" letter-spacing="0.6" fill="{c["muted"]}">OTHER MEMBERS</text>')
    if entry_up:
        add(f'<text x="{width - margin}" y="{entry_top - 12}" text-anchor="end" font-size="11.5" font-weight="700" letter-spacing="0.6" fill="{c["critical"]}">ENTRY POINTS · Internet or edge-proxy ingress</text>')
    if lower:
        add(f'<text x="{width - margin}" y="{lower_top - 4}" text-anchor="end" font-size="11.5" font-weight="700" letter-spacing="0.6" fill="{c["critical"]}">HIGH-VALUE HOSTS ON THE SHARED NETWORK</text>')
    for item in in_net:
        x, y = positions[item["name"]]
        ip = ", ".join(item.get("private_ips", []))
        lines: list[tuple[str, str]] = [(" · ".join(part for part in (ip, item["type"], item["location"]) if part), "muted")]
        lines += _chips(item)[:2] or [("no public ingress", "muted")]
        if _high_value(item):
            others = len(in_net) - 1
            lines = lines[:2] + [(f"reachable from {others} VM{'s' if others != 1 else ''}", "critical")]
        _vm_card(add, c, x, y, card_w, card_h, item, lines, _category(item))
    if outside:
        add(f'<rect x="{margin - 10}" y="{outside_top - 28}" width="{width - 2 * margin + 20}" height="{math.ceil(len(outside) / per_row) * (card_h + gap * 2) + 30}" rx="10" fill="none" stroke="{c["line"]}" stroke-dasharray="3 4"/>')
        add(f'<text x="{margin}" y="{outside_top - 10}" font-size="11.5" font-weight="700" letter-spacing="0.6" fill="{c["muted"]}">OUTSIDE THE PRIVATE NETWORK · reachable only through public interfaces and the cloud firewall</text>')
        for index, item in enumerate(outside):
            row, column = divmod(index, per_row)
            x = margin + column * (card_w + gap)
            y = outside_top + 6 + row * (card_h + gap * 2)
            lines = [(" · ".join(part for part in (item["type"], item["location"]) if part), "muted")]
            lines += _chips(item)[:2] or [("no public ingress", "muted")]
            _vm_card(add, c, x, y, card_w, card_h, item, lines, _category(item))
    if security_actions:
        _actions_panel(add, c, margin, actions_y, width - 2 * margin, security_actions, 4, title="RECOMMENDED SECURITY ACTIONS")

    add(f'<rect x="{margin}" y="{legend_y}" width="{width - 2 * margin}" height="70" rx="10" fill="{c["surface"]}" stroke="{c["line"]}"/>')
    add(f'<text x="{margin + 16}" y="{legend_y + 22}" font-size="11" font-weight="700" letter-spacing="0.6" fill="{c["muted"]}">LEGEND</text>')
    lx = margin + 16.0
    ly = legend_y + 48
    add(f'<path d="M {lx} {ly} L {lx + 30} {ly}" stroke="{c["line"]}" stroke-width="2"/>')
    add(f'<text x="{lx + 38}" y="{ly + 4}" font-size="11.5" fill="{c["text"]}">attached to the network</text>')
    lx += 200
    add(f'<path d="M {lx} {ly} L {lx + 30} {ly}" stroke="{c["critical"]}" stroke-width="1.8" opacity="0.7" marker-end="url(#arrow)"/>')
    add(f'<text x="{lx + 40}" y="{ly + 4}" font-size="11.5" fill="{c["text"]}">entry point → network → high-value host (all ports; cloud FW does not filter)</text>')
    lx += 470
    for key, label in (("world", "Internet ports"), ("edge", "Edge-proxy-only ports"), ("mesh", "Mesh VPN admin ports")):
        add(f'<text x="{lx}" y="{ly + 4}" font-size="11.5" font-weight="700" fill="{c[key]}">{escape(label)}</text>')
        lx += 22 + len(label) * 6.6
    add("</svg>")
    return "\n".join(out)


# ---------------------------------------------------------------- per-VM cost view

COMPONENT_COLORS = {"server": "#2f6fdb", "volumes": "#0f8b8d", "ipv4": "#6d4fc2", "backup": "#1f9d55"}


def _short(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _vm_status(node: dict[str, Any], has_saving: bool, storage_heavy: bool) -> tuple[str, str]:
    """One word per VM telling the owner whether to act: REVIEW, DEPRECATED, COST, or OK."""
    if node.get("exposure") in {"public", "critical"} or (node and node.get("networks") and _high_value(node)):
        return "REVIEW", "critical"
    if node.get("deprecated_type"):
        return "DEPRECATED", "public"
    if has_saving or storage_heavy:
        return "COST", "vpc"
    return "OK", "muted"


def render_cost_svg(
    topology: dict[str, Any], cost: dict[str, Any], title: str = "Per-VM monthly cost", theme: str = "light",
    actions: list[dict[str, Any]] | None = None,
) -> str:
    """Cards per VM sorted by monthly catalog cost, with component bars and the best candidate saving."""
    c = THEMES[theme]
    margin, card_w, card_h, gap, per_row = 28, 268, 112, 16, 5
    currency = cost.get("currency", "EUR")
    by_id = {item["id"]: item for item in topology["servers"]}
    rows = sorted(cost.get("servers", []), key=lambda item: -float(item.get("monthly_net", 0) or 0))
    best: dict[str, dict[str, Any]] = {}
    other_recs = []
    for rec in cost.get("recommendations", []):
        saving = float(rec.get("estimated_savings", {}).get("monthly", 0) or 0)
        for asset in rec.get("assets", []):
            if asset in by_id:
                if saving > float(best.get(asset, {}).get("estimated_savings", {}).get("monthly", 0) or 0):
                    best[asset] = rec
            else:
                other_recs.append(rec)
    top_cost = max((float(item.get("monthly_net", 0) or 0) for item in rows), default=1.0) or 1.0
    monthly = float(cost.get("current_catalog_estimate", {}).get("monthly_net", 0) or 0)
    savings = cost.get("identified_potential_savings", {})
    extras = cost.get("resource_components_net", {}) or {}
    extra_total = sum(float(value or 0) for value in extras.values())

    insights = cost_insights(cost)
    heavy = {str(item["asset_id"]) for item in insights.get("storage_heavy", [])}
    stateful = [item for item in topology["servers"] if item.get("volume_gb")]
    backed = sum(1 for item in stateful if item.get("backups"))
    cost_actions = [item for item in actions or [] if item.get("category") == "cost"]
    width = margin * 2 + per_row * card_w + (per_row - 1) * gap
    top = margin + HEADER_H + 20
    split_y = top
    grid_top = split_y + 78
    grid_rows = max(1, math.ceil(len(rows) / per_row))
    extras_y = grid_top + grid_rows * (card_h + gap) + 8
    actions_y = extras_y + (64 if (extra_total or other_recs) else 0)
    legend_y = actions_y + _actions_height(cost_actions, 5)
    height = legend_y + 70 + margin

    out: list[str] = []
    add = out.append
    _open_svg(add, c, width, height)
    metrics = any(item.get("cpu_samples") for item in rows)
    opportunities = (
        (str(insights.get("opportunities", 0)), f"need RAM/disk data · ≤ {currency} {insights.get('opportunities_monthly', 0):,.0f}/mo")
        if metrics
        else ("n/a", "not evaluated: no CPU metrics collected")
    )
    _header(
        add, c, width, margin, title,
        "Hetzner catalog prices, net · VAT excluded · traffic not included · not an invoice · "
        + ("CPU p95 from provider metrics" if metrics else "no CPU metrics collected"),
        [
            ("Monthly estimate", f"{currency} {monthly:,.0f}", f"{currency} {monthly * 12:,.0f} per year · {len(rows)} servers", c["text"]),
            ("Spend concentration", f"{insights.get('top3_share', 0):.0%}", f"top 3 VMs · top 5 = {insights.get('top5_share', 0):.0%}", c["text"]),
            ("Identifiable waste", f"{currency} {insights.get('waste_monthly', 0):,.2f}", "unused resources · no telemetry needed", c["public"] if insights.get("waste_monthly") else c["vpc"]),
            ("Optimization candidates", opportunities[0], opportunities[1], c["private"]),
            ("Expected savings", f"{currency} {float(savings.get('expected_monthly_net', 0) or 0):,.2f}", "waste + fully evidenced rightsizing", c["public"]),
            ("Provider backups", f"{backed}/{len(stateful)}", "stateful servers with backups on", c["public"] if backed < len(stateful) else c["vpc"]),
        ],
    )

    # Split bar: share of monthly cost per role tier.
    tiers: dict[str, float] = {}
    for item in rows:
        tier = by_id.get(item.get("asset_id"), {}).get("group", "other")
        tiers[tier] = tiers.get(tier, 0.0) + float(item.get("monthly_net", 0) or 0)
    total = sum(tiers.values()) or 1.0
    add(f'<text x="{margin}" y="{split_y + 14}" font-size="11.5" font-weight="700" letter-spacing="0.6" fill="{c["muted"]}">COST BY ROLE</text>')
    bar_x = float(margin)
    bar_w = width - 2 * margin
    for tier, value in sorted(tiers.items(), key=lambda item: -item[1]):
        share = value / total
        color = CATEGORY.get(tier, CATEGORY["other"])[0]
        segment = bar_w * share
        add(f'<rect x="{bar_x:.1f}" y="{split_y + 24}" width="{max(segment - 2, 1):.1f}" height="18" rx="4" fill="{color}"/>')
        label = next((name for key, name, _w in GROUPS if key == tier), "Other")
        if segment > 110:
            add(f'<text x="{bar_x + 8:.1f}" y="{split_y + 37}" font-size="11" font-weight="700" fill="#fff">{escape(label)} {share:.0%}</text>')
        add(f'<text x="{bar_x:.1f}" y="{split_y + 58}" font-size="10.5" fill="{c["muted"]}">{currency} {value:,.0f}</text>')
        bar_x += segment

    for index, item in enumerate(rows):
        row, column = divmod(index, per_row)
        x = margin + column * (card_w + gap)
        y = grid_top + row * (card_h + gap)
        node = by_id.get(item.get("asset_id"), {})
        category = _category(node) if node else "other"
        color, glyph = CATEGORY.get(category, CATEGORY["other"])
        add(f'<rect x="{x}" y="{y}" width="{card_w}" height="{card_h}" rx="9" fill="{c["surface"]}" stroke="{c["line"]}" filter="url(#shadow)"/>')
        _icon(add, x + 10, y + 12, glyph, color, 34)
        add(f'<text x="{x + 54}" y="{y + 24}" font-size="13" font-weight="700" fill="{c["text"]}">{escape(_short(str(item.get("name", "")), 17))}</text>')
        add(f'<text x="{x + card_w - 12}" y="{y + 26}" text-anchor="end" font-size="16" font-weight="800" fill="{c["text"]}">{currency} {float(item.get("monthly_net", 0) or 0):,.2f}</text>')
        cpu = item.get("cpu_p95_capacity_percent")
        detail = " · ".join(
            part for part in (
                str(item.get("server_type", "")),
                f"{item.get('cores', '?')}c/{item.get('memory_gb', '?')}G",
                node.get("location", ""),
                f"CPU p95 {cpu:.0f}%" if isinstance(cpu, (int, float)) else "",
                "stopped" if item.get("status") not in (None, "running") else "",
            ) if part
        )
        add(f'<text x="{x + 54}" y="{y + 42}" font-size="10.5" fill="{c["muted"]}">{escape(_short(detail, 38))}</text>')
        # Component bar scaled to the most expensive VM.
        components = item.get("components_net", {}) or {}
        bx = x + 12.0
        full = card_w - 24
        add(f'<rect x="{bx}" y="{y + 56}" width="{full}" height="10" rx="3" fill="{c["line"]}"/>')
        for key in ("server", "volumes", "ipv4", "backup"):
            value = float(components.get(key, 0) or 0)
            if value <= 0:
                continue
            segment = full * value / top_cost
            add(f'<rect x="{bx:.1f}" y="{y + 56}" width="{segment:.1f}" height="10" rx="2" fill="{COMPONENT_COLORS[key]}"/>')
            bx += segment
        parts = " · ".join(
            f"{key} {float(components.get(key, 0) or 0):,.2f}" for key in ("server", "volumes", "ipv4", "backup") if float(components.get(key, 0) or 0)
        )
        add(f'<text x="{x + 12}" y="{y + 82}" font-size="10.5" fill="{c["muted"]}">{escape(parts)}</text>')
        rec = best.get(str(item.get("asset_id")))
        status, status_color = _vm_status(node, rec is not None, str(item.get("asset_id")) in heavy)
        pill_w = 10 + len(status) * 6.6
        add(f'<rect x="{x + card_w - pill_w - 10}" y="{y - 8}" width="{pill_w:.1f}" height="16" rx="8" fill="{c[status_color]}"/>')
        add(f'<text x="{x + card_w - pill_w / 2 - 10:.1f}" y="{y + 3.5}" text-anchor="middle" font-size="9.5" font-weight="800" fill="#fff">{status}</text>')
        if rec:
            candidate = rec.get("candidate_state", {}).get("server_type") or {
                "HETZ-COST-001": "retire stopped server",
                "HETZ-COST-004": "retire volume",
            }.get(str(rec.get("rule_id")), "review")
            saving = float(rec.get("estimated_savings", {}).get("monthly", 0) or 0)
            line = f"→ {candidate} · −{currency} {saving:,.2f}/mo (to validate)"
            add(f'<text x="{x + 12}" y="{y + 100}" font-size="10.5" font-weight="700" fill="{c["vpc"]}">{escape(_short(line, 44))}</text>')
        elif node.get("deprecated_type"):
            add(f'<text x="{x + 12}" y="{y + 100}" font-size="10.5" font-weight="700" fill="{c["public"]}">deprecated type · see migration action</text>')
        elif str(item.get("asset_id")) in heavy:
            add(f'<text x="{x + 12}" y="{y + 100}" font-size="10.5" font-weight="700" fill="{c["public"]}">storage-heavy · review volume footprint</text>')

    if extra_total or other_recs:
        add(f'<rect x="{margin}" y="{extras_y}" width="{width - 2 * margin}" height="48" rx="10" fill="{c["surface"]}" stroke="{c["line"]}"/>')
        text = " · ".join(f"{key.replace('_', ' ')} {currency} {float(value or 0):,.2f}" for key, value in extras.items() if float(value or 0))
        recs = "; ".join(f"{rec.get('title', '')} (save {currency} {float(rec.get('estimated_savings', {}).get('monthly', 0) or 0):,.2f}/mo)" for rec in other_recs[:3])
        add(f'<text x="{margin + 16}" y="{extras_y + 20}" font-size="11.5" font-weight="700" fill="{c["text"]}">Outside servers: {escape(text or "none")}</text>')
        if recs:
            add(f'<text x="{margin + 16}" y="{extras_y + 38}" font-size="11" fill="{c["vpc"]}">{escape(recs)}</text>')

    if cost_actions:
        _actions_panel(add, c, margin, actions_y, width - 2 * margin, cost_actions, 5, currency, "RECOMMENDED COST ACTIONS")

    add(f'<rect x="{margin}" y="{legend_y}" width="{width - 2 * margin}" height="70" rx="10" fill="{c["surface"]}" stroke="{c["line"]}"/>')
    add(f'<text x="{margin + 16}" y="{legend_y + 22}" font-size="11" font-weight="700" letter-spacing="0.6" fill="{c["muted"]}">LEGEND</text>')
    lx = margin + 16.0
    for key, label in (("server", "server type"), ("volumes", "attached volumes"), ("ipv4", "primary IPv4"), ("backup", "backups")):
        add(f'<rect x="{lx}" y="{legend_y + 40}" width="22" height="10" rx="2" fill="{COMPONENT_COLORS[key]}"/>')
        add(f'<text x="{lx + 30}" y="{legend_y + 49}" font-size="11.5" fill="{c["text"]}">{label}</text>')
        lx += 44 + len(label) * 6.6
    add(f'<text x="{lx + 10}" y="{legend_y + 49}" font-size="11.5" fill="{c["muted"]}">Status: REVIEW = exposure or high-value host on a shared network · DEPRECATED · COST = saving or storage-heavy · OK. Bars scale to the most expensive VM.</text>')
    add("</svg>")
    return "\n".join(out)


# ---------------------------------------------------------------- per-VM host layers view
def _wrap(text: str, limit: int) -> list[str]:
    words, lines, line = text.split(), [], ""
    for word in words:
        if line and len(line) + 1 + len(word) > limit:
            lines.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    return [*lines, line] if line else lines or [""]


def render_host_svg(
    hosts: list[dict[str, Any]], title: str = "Per-VM host layers", theme: str = "light",
    actions: list[dict[str, Any]] | None = None, missing: int = 0,
) -> str:
    """One row per server with a host bundle: each filtering layer, and what passes all of them."""
    c = THEMES[theme]
    margin, gap = 28, 14
    width = 1500
    stage_w = (width - 2 * margin - 32 - 4 * 34) / 5
    chip_w, chip_h, per_row = 228, 40, 6

    def panel_h(host: dict[str, Any]) -> float:
        rows = math.ceil(len(host["containers"]) / per_row)
        return 64 + 92 + (26 + rows * (chip_h + 8) if rows else 0) + 14

    top = margin + HEADER_H + 20
    heights = [panel_h(host) for host in hosts]
    empty_h = 120 if not hosts else 0
    actions_y = top + sum(heights) + gap * len(hosts) + empty_h + 10
    security_actions = [item for item in actions or [] if item.get("category") == "security"]
    height = actions_y + _actions_height(security_actions, 5) + margin

    out: list[str] = []
    add = out.append
    _open_svg(add, c, width, height)
    exposed = sum(1 for host in hosts if host["reachable"] not in {"none", "unknown"})
    bypass = sum(1 for host in hosts if host["docker_bypass"])
    unfiltered = sum(1 for host in hosts if "filters nothing" in str(host["engine"]))
    _header(
        add, c, width, margin, title,
        "cloud firewall ∩ host firewall ∩ listener = reachable · Docker-published ports skip UFW/nftables input rules · from owner-run host bundles",
        [
            ("Hosts with evidence", str(len(hosts)), f"{missing} server(s) without a bundle", c["text"]),
            ("Reachable end to end", str(exposed), "servers with a port open through every layer", c["critical"] if exposed else c["vpc"]),
            ("Docker bypass", str(bypass), "servers publishing past the host firewall", c["critical"] if bypass else c["vpc"]),
            ("No host firewall", str(unfiltered), "cloud firewall is the only layer", c["public"] if unfiltered else c["vpc"]),
            ("Containers", str(sum(len(host["containers"]) for host in hosts)), "seen in docker inspect", c["text"]),
        ],
    )
    if not hosts:
        add(f'<rect x="{margin}" y="{top}" width="{width - 2 * margin}" height="100" rx="12" fill="{c["surface"]}" stroke="{c["line"]}"/>')
        add(f'<text x="{margin + 20}" y="{top + 44}" font-size="15" font-weight="700" fill="{c["text"]}">No host evidence in this snapshot</text>')
        add(f'<text x="{margin + 20}" y="{top + 68}" font-size="12.5" fill="{c["muted"]}">Run `hetzner-audit host-bundle` on each server (owner-run, read-only) and pass the output with --host-bundle.</text>')
    y = float(top)
    for host, panel in zip(hosts, heights, strict=True):
        reachable = host["reachable"] not in {"none", "unknown"}
        add(f'<rect x="{margin}" y="{y}" width="{width - 2 * margin}" height="{panel}" rx="12" fill="{c["surface"]}" stroke="{c["critical"] if reachable else c["line"]}" stroke-width="{1.6 if reachable else 1}" filter="url(#shadow)"/>')
        _icon(add, margin + 16, y + 14, "server", CATEGORY["app"][0], 34)
        add(f'<text x="{margin + 60}" y="{y + 30}" font-size="15" font-weight="800" fill="{c["text"]}">{escape(host["name"])}</text>')
        add(f'<text x="{margin + 60}" y="{y + 48}" font-size="11.5" fill="{c["muted"]}">{escape(host["subtitle"])}</text>')
        stages = [
            ("CLOUD FIREWALL", f"admits {host['cloud_admits']}", c["text"]),
            (f"HOST FIREWALL · {str(host['engine']).split(' ')[0].upper()}",
             "could not be read" if "unreadable" in str(host["engine"])
             else f"admits {host['host_firewall_admits']}" + (" (filters nothing)" if "filters nothing" in str(host["engine"]) else ""),
             c["muted"] if "unreadable" in str(host["engine"]) else c["public"] if "filters nothing" in str(host["engine"]) else c["text"]),
            ("PUBLIC LISTENERS", host["public_listeners"], c["text"]),
            ("DOCKER PUBLISHED", ("bypass " + ", ".join(map(str, host["docker_bypass"]))) if host["docker_bypass"] else "no bypass", c["critical"] if host["docker_bypass"] else c["vpc"]),
            ("REACHABLE FROM INTERNET", host["reachable"],
             c["critical"] if reachable else c["muted"] if host["reachable"] == "unknown" else c["vpc"]),
        ]
        private = host.get("private_reachable")
        sx = margin + 16.0
        sy = y + 64
        for index, (label, value, color) in enumerate(stages):
            last = index == len(stages) - 1
            add(f'<rect x="{sx:.1f}" y="{sy}" width="{stage_w:.1f}" height="78" rx="9" fill="{c["band"]}" stroke="{color if last else c["line"]}" stroke-width="{1.6 if last else 1}"/>')
            add(f'<text x="{sx + 12:.1f}" y="{sy + 20}" font-size="10.5" font-weight="700" letter-spacing="0.5" fill="{c["muted"]}">{escape(label)}</text>')
            for line_index, line in enumerate(_wrap(value, 30)[:3]):
                add(f'<text x="{sx + 12:.1f}" y="{sy + 40 + line_index * 15}" font-size="12.5" font-weight="700" fill="{color}">{escape(line)}</text>')
            if last and private is not None:
                add(f'<text x="{sx + 12:.1f}" y="{sy + 66}" font-size="11" font-weight="700" fill="{c["public"] if private != "none" else c["muted"]}">'
                    f'{escape(_short("private network: " + private, 38))}</text>')
            if not last:
                ax = sx + stage_w + 4
                add(f'<path d="M {ax:.1f} {sy + 39} L {ax + 24:.1f} {sy + 39}" stroke="{c["muted"]}" stroke-width="1.6" marker-end="url(#arrow)"/>')
                add(f'<text x="{ax + 12:.1f}" y="{sy + 32}" text-anchor="middle" font-size="12" font-weight="800" fill="{c["muted"]}">∩</text>')
            sx += stage_w + 34
        if host["containers"]:
            cy = sy + 92
            add(f'<text x="{margin + 16}" y="{cy + 12}" font-size="10.5" font-weight="700" letter-spacing="0.5" fill="{c["muted"]}">CONTAINERS</text>')
            for index, item in enumerate(host["containers"]):
                row, column = divmod(index, per_row)
                cx = margin + 16 + column * (chip_w + 10)
                ry = cy + 22 + row * (chip_h + 8)
                risky = bool(item["risks"])
                add(f'<rect x="{cx}" y="{ry}" width="{chip_w}" height="{chip_h}" rx="8" fill="{c["surface"]}" stroke="{c["critical"] if risky else c["line"]}"/>')
                add(f'<text x="{cx + 10}" y="{ry + 16}" font-size="11.5" font-weight="700" fill="{c["text"]}">{escape(_short(item["name"], 30))}</text>')
                detail = item["risks"] or item["ports"] or "not published"
                add(f'<text x="{cx + 10}" y="{ry + 31}" font-size="10.5" fill="{c["critical"] if risky or item["bypass"] else c["muted"]}">{escape(_short(detail, 36))}</text>')
        y += panel + gap
    if security_actions:
        _actions_panel(add, c, margin, actions_y, width - 2 * margin, security_actions, 5, title="HOST AND SECURITY ACTIONS")
    add("</svg>")
    return "\n".join(out)


# ---------------------------------------------------------------- posture overview
POSTURE_DOMAINS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Network exposure", ("HETZ-NET-", "HETZ-FW-", "HETZ-LB-", "HETZ-XLY-", "HETZ-K8S-001", "HETZ-ROB-001", "HETZ-ROB-002", "HETZ-ROB-003", "HETZ-ROB-005")),
    ("Host and runtime", ("HETZ-HOST-", "HETZ-SSH-", "HETZ-DKR-", "HETZ-K8S-002", "HETZ-VULN-")),
    ("Data services", ("HETZ-PG-", "HETZ-RDS-", "HETZ-OBJ-", "HETZ-STO-")),
    ("Identity and access", ("HETZ-KEY-", "HETZ-ATT-", "HETZ-CHG-")),
    ("Resilience", ("HETZ-BCP-", "HETZ-GOV-001", "HETZ-PLC-", "HETZ-CERT-", "HETZ-DNS-", "HETZ-IMG-")),
    ("Governance and drift", ("HETZ-GOV-", "HETZ-IAC-", "HETZ-XPR-")),
)
SEVERITIES = ("critical", "high", "medium", "low", "info")


def posture_matrix(findings: list[Any]) -> dict[str, dict[str, dict[str, int]]]:
    """domain -> severity (or 'unscored' for hypotheses) -> {'confirmed': n, 'needs_validation': n}."""
    matrix: dict[str, dict[str, dict[str, int]]] = {name: {} for name, _ in POSTURE_DOMAINS}
    for finding in findings:
        status = finding.status.value
        if status == "rejected":
            continue
        domain = next((name for name, prefixes in POSTURE_DOMAINS if finding.rule_id.startswith(prefixes)), "Governance and drift")
        # Hypotheses carry no severity; place them by the rule's candidate severity when known.
        severity = finding.severity.value if finding.severity else str(finding.metadata.get("candidate_severity") or "unscored")
        cell = matrix[domain].setdefault(severity, {"confirmed": 0, "needs_validation": 0})
        cell[status] = cell.get(status, 0) + 1
    return matrix


def render_posture_svg(
    matrix: dict[str, dict[str, dict[str, int]]], coverage: list[tuple[str, int, str]], sources: list[str],
    title: str = "Security posture", theme: str = "light", actions: list[dict[str, Any]] | None = None,
    details: list[str] | None = None,
) -> str:
    source_count = len(sources)
    sources = [*sources, *(details or [])]
    c = THEMES[theme]
    margin, width = 28, 1500
    columns = [*SEVERITIES, "unscored"]
    label_w, cell_w, row_h = 230, (1500 - 2 * 28 - 32 - 230) / 6, 58
    grid_top = margin + HEADER_H + 20
    grid_h = 48 + len(matrix) * row_h + 16
    side_top = grid_top + grid_h + 20
    cov_h = 44 + len(coverage) * 30 + 12
    src_h = 44 + max(1, len(sources)) * 20 + 12
    actions_y = side_top + max(cov_h, src_h) + 20
    height = actions_y + _actions_height(actions, 5) + margin
    confirmed = sum(cell.get("confirmed", 0) for row in matrix.values() for cell in row.values())
    pending = sum(cell.get("needs_validation", 0) for row in matrix.values() for cell in row.values())
    severe = sum(cell.get("confirmed", 0) for row in matrix.values() for sev, cell in row.items() if sev in {"critical", "high"})
    out: list[str] = []
    add = out.append
    _open_svg(add, c, width, height)
    _header(
        add, c, width, margin, title, "confirmed = evidence complete · to validate = a layer is not observed yet · rejected findings are not shown",
        [
            ("Confirmed", str(confirmed), "evidence complete", c["critical"] if confirmed else c["vpc"]),
            ("Critical + high", str(severe), "confirmed only", c["critical"] if severe else c["vpc"]),
            ("To validate", str(pending), "hypotheses with a missing layer", c["public"] if pending else c["vpc"]),
            ("Evidence sources", str(source_count), "API, host, IaC, owner", c["text"]),
        ],
    )
    add(f'<rect x="{margin}" y="{grid_top}" width="{width - 2 * margin}" height="{grid_h}" rx="12" fill="{c["surface"]}" stroke="{c["line"]}" filter="url(#shadow)"/>')
    heads = {"critical": c["critical"], "high": c["critical"], "medium": c["public"], "low": c["location"], "info": c["muted"], "unscored": c["muted"]}
    for index, column in enumerate(columns):
        x = margin + 16 + label_w + index * cell_w
        add(f'<text x="{x + cell_w / 2:.1f}" y="{grid_top + 30}" text-anchor="middle" font-size="11" font-weight="800" letter-spacing="0.6" fill="{heads[column]}">{escape(column.upper() if column != "unscored" else "TO VALIDATE")}</text>')
    for row_index, (domain, row) in enumerate(matrix.items()):
        y = grid_top + 48 + row_index * row_h
        add(f'<line x1="{margin + 16}" y1="{y}" x2="{width - margin - 16}" y2="{y}" stroke="{c["line"]}"/>')
        add(f'<text x="{margin + 24}" y="{y + 34}" font-size="13.5" font-weight="700" fill="{c["text"]}">{escape(domain)}</text>')
        for index, column in enumerate(columns):
            cell = row.get(column, {})
            done, todo = cell.get("confirmed", 0), cell.get("needs_validation", 0)
            x = margin + 16 + label_w + index * cell_w
            if not done and not todo:
                add(f'<text x="{x + cell_w / 2:.1f}" y="{y + 34}" text-anchor="middle" font-size="13" fill="{c["line"]}">·</text>')
                continue
            color = heads[column]
            add(f'<rect x="{x + 10:.1f}" y="{y + 10}" width="{cell_w - 20:.1f}" height="{row_h - 20}" rx="9" fill="{color}" opacity="{0.9 if done else 0.18}"/>')
            text = f"{done}" + (f" +{todo}?" if todo else "") if done else f"{todo}?"
            add(f'<text x="{x + cell_w / 2:.1f}" y="{y + 35}" text-anchor="middle" font-size="15" font-weight="800" fill="{"#fff" if done else c["text"]}">{escape(text)}</text>')
    half = (width - 2 * margin - 16) / 2
    add(f'<rect x="{margin}" y="{side_top}" width="{half}" height="{cov_h}" rx="12" fill="{c["surface"]}" stroke="{c["line"]}"/>')
    add(f'<text x="{margin + 16}" y="{side_top + 24}" font-size="11" font-weight="700" letter-spacing="0.6" fill="{c["muted"]}">WHAT THIS AUDIT KNOWS</text>')
    for index, (name, percent, basis) in enumerate(coverage):
        y = side_top + 44 + index * 30
        add(f'<text x="{margin + 16}" y="{y + 12}" font-size="12" font-weight="700" fill="{c["text"]}">{escape(name)}</text>')
        bar_x, bar_w = margin + 200, half - 200 - 70
        add(f'<rect x="{bar_x}" y="{y + 2}" width="{bar_w:.1f}" height="12" rx="6" fill="{c["band"]}" stroke="{c["line"]}"/>')
        fill = c["vpc"] if percent >= 80 else c["public"] if percent >= 30 else c["critical"]
        add(f'<rect x="{bar_x}" y="{y + 2}" width="{max(0, bar_w * percent / 100):.1f}" height="12" rx="6" fill="{fill}"/>')
        add(f'<text x="{bar_x + bar_w + 10:.1f}" y="{y + 13}" font-size="12" font-weight="800" fill="{fill}">{percent}%</text>')
        add(f'<title>{escape(basis)}</title>')
    sx = margin + half + 16
    add(f'<rect x="{sx}" y="{side_top}" width="{half}" height="{src_h}" rx="12" fill="{c["surface"]}" stroke="{c["line"]}"/>')
    add(f'<text x="{sx + 16}" y="{side_top + 24}" font-size="11" font-weight="700" letter-spacing="0.6" fill="{c["muted"]}">EVIDENCE SOURCES</text>')
    for index, line in enumerate(sources or ["Hetzner Cloud API only"]):
        add(f'<text x="{sx + 16}" y="{side_top + 48 + index * 20}" font-size="12" fill="{c["text"]}">• {escape(_short(line, 112))}</text>')
    if actions:
        _actions_panel(add, c, margin, actions_y, width - 2 * margin, actions, 5)
    add("</svg>")
    return "\n".join(out)
