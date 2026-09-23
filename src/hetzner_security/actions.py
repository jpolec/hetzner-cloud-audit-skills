"""Recommended actions: turn findings and cost evidence into ranked, owner-ready next steps.

Each action states what to do, why, how sure the tool is (evidence level with a reason), the
risk of acting, the monthly saving when one is known, and the concrete next step. Nothing here
changes infrastructure; actions are plans for a human.
"""

from __future__ import annotations

import re
from typing import Any

from .cost import _available, _location, _type_price
from .models import Asset, Finding, FindingStatus, Snapshot
from .text import md

# Cost rules that need no utilization telemetry: the resource is billed and unused as observed.
WASTE_RULES = {"HETZ-COST-001", "HETZ-COST-004", "HETZ-COST-005", "HETZ-COST-006", "HETZ-COST-007"}
TELEMETRY_RULES = {"HETZ-COST-002", "HETZ-COST-003"}
STORAGE_HEAVY_RATIO = 0.5  # volume cost above half the compute cost is worth a look
STORAGE_HEAVY_MIN = 10.0  # ...but only when the volume spend itself is material (per month)


def evidence_level(finding: Finding) -> tuple[str, str]:
    """HIGH/MEDIUM/LOW plus the reason, derived from verification status and evidence kinds."""
    kinds = {item.kind for item in finding.evidence}
    if finding.status == FindingStatus.CONFIRMED:
        if kinds & {"listening_socket", "host_firewall_allow", "service_bind", "application_policy"}:
            return "HIGH", "provider and host/runtime evidence agree"
        if "owner_attestation" in kinds:
            return "MEDIUM", "owner attestation (console checklist)"
        if any(item.source == "host_bundle" or item.asset_id.startswith("host:") for item in finding.evidence) or kinds & {
            "docker_published", "sshd_effective_config", "host_firewall_decision", "container_runtime", "pg_hba_rule"
        }:
            return "HIGH", "host evidence bundle"
        return "HIGH", "explicit provider state"
    if finding.status == FindingStatus.REJECTED:
        return "LOW", "refuted by an observed control"
    if "owner_attestation" in kinds:
        return "LOW", "not yet verified by the owner"
    if any(item.source == "host_bundle" or item.asset_id.startswith("host:") for item in finding.evidence):
        return "MEDIUM", "host configuration observed; no network path to it was evidenced"
    if any(item.source in {"robot_api", "object_storage_api", "kubernetes", "terraform"} for item in finding.evidence):
        return "MEDIUM", "explicit provider state; owner or host confirmation needed"
    if "provider_action" in kinds:
        return "MEDIUM", "provider action history shows the change; intent not known"
    if "docker_user_chain" in kinds:
        return "MEDIUM", "host evidence observed; DOCKER-USER rules need review"
    if kinds & {"firewall_rule", "private_network", "private_network_unfiltered", "public_interface"}:
        return "MEDIUM", "cloud path observed; host firewall, listener, and auth not observed"
    return "LOW", "absence of evidence; depends on collector coverage and owner intent"


def _servers(snapshot: Snapshot) -> dict[str, Asset]:
    return {asset.id: asset for asset in snapshot.assets if asset.type == "server"}


def replacement_candidate(snapshot: Snapshot, server: Asset) -> dict[str, Any] | None:
    """Cheapest available type with the same architecture and at least the same cores and memory.

    Also reports the same-family successor when the catalog lists it as unavailable, and the
    cheapest ARM alternative (a different architecture, so it carries compatibility risk).
    """
    current = server.properties.get("server_type")
    if not isinstance(current, dict):
        return None
    location = _location(server)
    current_price = _type_price(server_type_asset(current), location) or _price_of(snapshot, str(current.get("name")), location)
    options = []
    unavailable_family = []
    arm = []
    for item in snapshot.assets:
        props = item.properties
        if (
            item.type != "server_type"
            or props.get("deprecated") is True
            or int(props.get("cores", 0) or 0) < int(current.get("cores", 0) or 0)
            or float(props.get("memory", 0) or 0) < float(current.get("memory", 0) or 0)
        ):
            continue
        price = _type_price(item, location)
        if price is None:
            continue
        same_family = props.get("category") == current.get("category") and props.get("cpu_type") == current.get("cpu_type")
        if props.get("architecture") != current.get("architecture"):
            if props.get("architecture") == "arm" and _available(item, location):
                arm.append((price, item.name))
            continue
        if not _available(item, location):
            if same_family:
                unavailable_family.append((price, item.name))
            continue
        options.append((0 if same_family else 1, price, item))
    if not options:
        return None
    _family, price, best = min(options, key=lambda option: (option[0], option[1]))
    return {
        "server_type": best.name,
        "monthly": price,
        "delta": round(price - current_price, 2) if current_price is not None else None,
        "family_unavailable": min(unavailable_family)[1] if unavailable_family else None,
        "arm": {"server_type": min(arm)[1], "delta": round(min(arm)[0] - current_price, 2) if current_price is not None else None} if arm else None,
    }


def server_type_asset(value: dict[str, Any]) -> Asset:
    return Asset(f"embedded:{value.get('name')}", "server_type", str(value.get("name")), value)


def _price_of(snapshot: Snapshot, type_name: str, location: str) -> float | None:
    for item in snapshot.assets:
        if item.type == "server_type" and item.name == type_name:
            return _type_price(item, location)
    return None


def cost_insights(cost: dict[str, Any] | None) -> dict[str, Any]:
    """Waste vs telemetry-bound opportunities, spend concentration, storage-heavy servers, IPv4 spend."""
    if not cost:
        return {}
    recs = cost.get("recommendations", [])
    waste = [rec for rec in recs if rec.get("rule_id") in WASTE_RULES]
    telemetry = [rec for rec in recs if rec.get("rule_id") in TELEMETRY_RULES]
    servers = sorted(cost.get("servers", []), key=lambda item: -float(item.get("monthly_net", 0) or 0))
    total = sum(float(item.get("monthly_net", 0) or 0) for item in servers) or 1.0

    def share(count: int) -> float:
        return sum(float(item.get("monthly_net", 0) or 0) for item in servers[:count]) / total

    storage_heavy = [
        {
            "name": item.get("name"),
            "asset_id": item.get("asset_id"),
            "volumes": float(item.get("components_net", {}).get("volumes", 0) or 0),
            "server": float(item.get("components_net", {}).get("server", 0) or 0),
        }
        for item in servers
        if float(item.get("components_net", {}).get("server", 0) or 0) > 0
        and float(item.get("components_net", {}).get("volumes", 0) or 0) >= STORAGE_HEAVY_MIN
        and float(item.get("components_net", {}).get("volumes", 0) or 0)
        > STORAGE_HEAVY_RATIO * float(item.get("components_net", {}).get("server", 0) or 0)
    ]
    ipv4 = [item for item in servers if float(item.get("components_net", {}).get("ipv4", 0) or 0) > 0]
    by_asset: dict[str, float] = {}
    for rec in telemetry:
        saving = float(rec.get("estimated_savings", {}).get("monthly", 0) or 0)
        for asset in rec.get("assets", []):
            by_asset[asset] = max(by_asset.get(asset, 0.0), saving)
    return {
        "waste_monthly": round(sum(float(rec.get("estimated_savings", {}).get("monthly", 0) or 0) for rec in waste), 2),
        "waste": waste,
        "opportunities": len(by_asset),
        "opportunities_monthly": round(sum(by_asset.values()), 2),
        "metrics_collected": any(item.get("cpu_samples") for item in servers),
        "top3_share": share(3),
        "top5_share": share(5),
        "storage_heavy": storage_heavy,
        "ipv4_count": len(ipv4),
        "ipv4_monthly": round(sum(float(item.get("components_net", {}).get("ipv4", 0) or 0) for item in ipv4), 2),
    }


def coverage(snapshot: Snapshot, cost: dict[str, Any] | None) -> list[tuple[str, int, str]]:
    """What the audit actually knows, as (dimension, percent, basis)."""
    servers = list(_servers(snapshot).values())
    count = len(servers) or 1
    cost_rows = cost.get("servers", []) if cost else []
    priced = sum(1 for item in cost_rows if float(item.get("monthly_net", 0) or 0) > 0)
    utilization = sum(1 for item in cost_rows if item.get("cpu_samples"))
    owned = sum(1 for item in servers if item.labels.get("owner") or item.labels.get("project"))
    stateful = [item for item in servers if item.properties.get("stateful")]
    backed = sum(1 for item in stateful if item.properties.get("backup_enabled"))
    runtime = sum(
        1
        for item in servers
        if "host_firewall" in item.properties or "listening_ports" in item.properties
    )
    guest = sum(1 for item in cost_rows if item.get("guest_evidence_complete"))
    return [
        ("Cost", round(100 * priced / count), "catalog price found per server"),
        ("CPU utilization", round(100 * utilization / count), "provider CPU metrics (RAM/disk never)"),
        ("Ownership", round(100 * owned / count), "owner or project label"),
        ("Provider backups", round(100 * backed / (len(stateful) or 1)), f"of {len(stateful)} stateful servers"),
        ("RAM and disk telemetry", round(100 * guest / count), "node exporter via `--node-metrics`, full window"),
        ("Host/runtime evidence", round(100 * runtime / count), "host firewall, listeners, service config (`--host-bundle`)"),
    ]


def provenance(snapshot: Snapshot, cost: dict[str, Any] | None) -> list[str]:
    collected = str(snapshot.metadata.get("collected_at", "unknown"))[:16].replace("T", " ")
    lines = [
        f"Snapshot: {collected} UTC · collector {snapshot.metadata.get('collector', 'fixture')} {snapshot.metadata.get('collector_version', '')}".rstrip(),
    ]
    meta = snapshot.metadata
    sources = ["Hetzner Cloud API (GET requests)"]
    bundles = [item for item in meta.get("host_bundles") or [] if item.get("status") == "merged"]
    host_facts = [asset for asset in snapshot.assets if asset.type == "server"
                  and ("host_firewall" in asset.properties or "listening_ports" in asset.properties)]
    if bundles:
        sources.append(f"host bundles for {len(bundles)} server(s), run by the owner")
    elif host_facts:
        sources.append(f"host facts supplied in the snapshot for {len(host_facts)} server(s)")
    for key, label in (("terraform", "Terraform JSON"), ("node_metrics", "node exporter telemetry"),
                       ("kubernetes", "kubectl listing"), ("attestations", "owner checklist answers")):
        if meta.get(key):
            sources.append(label)
    coverage_keys = meta.get("coverage") or {}
    if "robot_server" in coverage_keys:
        sources.append("Hetzner Robot API")
    if "bucket" in coverage_keys:
        sources.append("Object Storage S3 API")
    if meta.get("projects"):
        sources.append(f"{len(meta['projects'])} merged project snapshot(s)")
    lines.append("Evidence sources: " + "; ".join(sources) + ".")
    if not bundles and not host_facts:
        lines.append("No host evidence: host firewall, listeners, and service configuration were not observed (add `--host-bundle`).")
    if cost:
        lines.append(
            f"Pricing: current Hetzner catalog, net ({cost.get('currency', 'EUR')}), VAT excluded; traffic overage from current-period usage only; invoice reconciliation not performed."
        )
    return lines


def _names(snapshot: Snapshot, ids: list[str]) -> list[str]:
    lookup = {asset.id: asset.name for asset in snapshot.assets}
    return [lookup.get(item, item) for item in ids]


def build_actions(snapshot: Snapshot, findings: list[Finding], cost: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Ranked actions; security exposure first, then segmentation, lifecycle, waste, hygiene."""
    servers = _servers(snapshot)
    actions: list[dict[str, Any]] = []
    by_rule: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.status != FindingStatus.REJECTED:
            by_rule.setdefault(finding.rule_id, []).append(finding)

    def add(priority: int, title: str, why: str, finding: Finding | None, level: tuple[str, str] | None,
            risk: str, saving: float | None, next_step: str, rules: list[str], category: str | None = None,
            commands: list[str] | None = None) -> None:
        category = category or (
            "security" if priority < 40 else "cost" if priority in {40, 50, 80, 90} else "resilience" if priority < 90 else "hygiene"
        )
        level = level or (evidence_level(finding) if finding else ("MEDIUM", "derived from provider state"))
        actions.append(
            {
                "priority": priority,
                "title": title,
                "why": why,
                "evidence_level": level[0],
                "evidence_reason": level[1],
                "risk": risk,
                "saving_monthly": saving,
                "next_step": next_step,
                "rules": rules,
                "category": category,
                "commands": commands or [],
            }
        )

    for rule in ("HETZ-NET-001", "HETZ-NET-002", "HETZ-NET-003", "HETZ-NET-004", "HETZ-NET-005"):
        for finding in by_rule.get(rule, []):
            add(10, f"Close public exposure: {finding.title}", finding.observation, finding, None, "low", None,
                "Remove the 0.0.0.0/0 rule in IaC or restrict it to known sources; then confirm the service is unreachable from outside.", [rule])
    for finding in by_rule.get("HETZ-NET-006", []):
        name = _names(snapshot, finding.assets[:1])[0]
        edge = finding.title.split("bypassing ", 1)[-1] if "bypassing " in finding.title else "the edge proxy"
        add(15, f"Restrict {name} web ports to {edge}, or confirm direct access is intended", finding.observation, finding, None, "low", None,
            f"Limit tcp/80 and tcp/443 on {name}'s cloud firewall to {edge} ranges in IaC, or publish through a tunnel and close them. "
            "On the host, check that Docker does not publish 80/443, because Docker bypasses UFW.", ["HETZ-NET-006"])
    lateral = by_rule.get("HETZ-XLY-002", [])
    if lateral:
        targets = sorted({name for finding in lateral for name in _names(snapshot, finding.assets[1:2])})
        members = sum(1 for server in servers.values() if server.properties.get("private_net"))
        add(20, f"Segment high-value hosts on the shared private network ({', '.join(targets)})",
            f"Blast radius: compromise of any of the {members - 1} other members gives L3 access to {', '.join(targets)} on every port. "
            "Hetzner Cloud Firewalls do not filter private networks; only host firewalls, localhost binds, and service authentication stop it.",
            lateral[0], ("HIGH", "network membership is explicit provider state; host controls not observed"), "medium", None,
            "Enforce a host firewall on the private interface that admits only required sources and ports, or move these hosts to a dedicated network.", ["HETZ-XLY-002"])
    outside_sensitive = [
        server for server in servers.values()
        if not server.properties.get("private_net")
        and any(token in (server.labels.get("role", "") + server.name).lower() for token in ("vault", "auth", "identity", "secret"))
    ]
    if outside_sensitive:
        names = ", ".join(sorted(server.name for server in outside_sensitive))
        add(30, f"Confirm the management path to {names}",
            "These identity/secrets hosts are outside every private network. Only public interfaces and the cloud firewall reach them, so access presumably runs over Tailscale.",
            None, ("LOW", "intent cannot be read from provider state"), "low", None,
            "Document the intended access path. If VPC workloads must reach them, attach them deliberately; otherwise record the isolation as a control.", [])
    for finding in by_rule.get("HETZ-GOV-003", []):
        for server_id in finding.assets:
            server = servers.get(server_id)
            if server is None:
                continue
            current = server.properties.get("server_type", {})
            candidate = replacement_candidate(snapshot, server)
            if candidate:
                def signed(value: float | None) -> str:
                    return "unknown" if value is None else f"{'+' if value > 0 else '−' if value < 0 else '±'}{abs(value):.2f}/mo"

                delta = candidate["delta"]
                why = f"{server.name} runs deprecated {current.get('name')}."
                if candidate.get("family_unavailable"):
                    why += f" Same-family successor {candidate['family_unavailable']} is listed as unavailable in {_location(server)} right now."
                why += f" Available replacement: {candidate['server_type']} (same architecture, ≥ cores and memory), cost delta {signed(delta)}."
                if candidate.get("arm"):
                    why += f" ARM alternative: {candidate['arm']['server_type']} ({signed(candidate['arm']['delta'])}), which needs multi-arch images and a benchmark."
                saving = -delta if delta is not None and delta < 0 else None
            else:
                why = f"{server.name} runs deprecated {current.get('name')}; no current replacement found in the catalog."
                saving = None
            add(40, f"Migrate {server.name} off deprecated {current.get('name')}", why, finding, None, "medium", saving,
                "Plan a resize or rebuild during a maintenance window, update IaC, and keep a snapshot for rollback.", ["HETZ-GOV-003"])
    insights = cost_insights(cost)
    for rec in insights.get("waste", []):
        saving = float(rec.get("estimated_savings", {}).get("monthly", 0) or 0)
        names = ", ".join(_names(snapshot, rec.get("assets", [])))
        add(50, f"{rec.get('title', 'Retire unused resource')}: {names}",
            "Billed and unused in this snapshot. Attachment history and owner are not visible in the API.",
            None, ("MEDIUM", "unused now; history and owner unknown"), "low", saving,
            "Confirm the owner and any restore dependency, snapshot if unsure, then delete through IaC.", [str(rec.get("rule_id"))])
    for finding in by_rule.get("HETZ-GOV-001", []):
        lookup = {asset.id: asset for asset in snapshot.assets}
        protection_commands = [
            f"hcloud {lookup[asset_id].type} enable-protection {_shell_name(lookup[asset_id].name)} delete"
            for asset_id in finding.assets
            if asset_id in lookup and lookup[asset_id].type in {"server", "volume", "network"}
        ]
        add(60, f"Enable deletion protection ({len(finding.assets)} resources)", finding.observation, finding, None, "low", None,
            "Set protection.delete=true in IaC for production servers, volumes, networks, and Storage Boxes.", ["HETZ-GOV-001"],
            commands=protection_commands[:12] + ([f"# … and {len(protection_commands) - 12} more"] if len(protection_commands) > 12 else []))
    backups = by_rule.get("HETZ-BCP-001", [])
    if backups:
        boxes = [asset.name for asset in snapshot.assets if asset.type == "storage_box"]
        add(70, f"Define and test backups for {len(backups)} stateful servers",
            "Provider backups are off." + (f" Storage Box {', '.join(boxes)} exists, so application-level backups may cover this." if boxes else ""),
            backups[0], None, "low", None,
            "Record which mechanism protects each volume and run one restore test; enable provider backups (+20% of the server price) where none exists.", ["HETZ-BCP-001"])
    for item in (cost or {}).get("traffic", {}).get("near_quota", []):
        add(48, f"Traffic on {item['name']} is at {item['used_percent']:.0f}% of the included quota",
            "Outgoing traffic beyond the included quota is billed per TB; the period is not over yet.",
            None, ("HIGH", "usage reported by the Hetzner API for this billing period"), "low",
            item.get("overage_net") or None,
            "Check what is sending the traffic (backups, public downloads, replication) and move bulk transfers onto the private network or a CDN.", [], "cost")
    if insights.get("storage_heavy"):
        names = ", ".join(str(item["name"]) for item in insights["storage_heavy"])
        add(80, f"Review storage footprint: {names}",
            "Volume cost exceeds half of the compute cost. That is a cost-structure signal, not a defect.",
            None, ("MEDIUM", "cost structure from catalog prices; filesystem usage not observed"), "low", None,
            "Check filesystem usage, retention, and whether cold data belongs on a Storage Box or Object Storage.", [])
    if insights.get("opportunities"):
        add(90, f"Collect RAM and disk telemetry for {insights['opportunities']} optimization candidates",
            f"CPU-based candidates add up to {insights['opportunities_monthly']:.2f}/mo, but none can be confirmed without RAM, disk, owner intent, and rollback.",
            None, ("LOW", "optimization hypothesis from CPU only"), "medium", None,
            "Export 30 days of RAM and disk p95 (node exporter or Prometheus) and rerun `hetzner-audit cost`.", ["HETZ-COST-002", "HETZ-COST-003"])
    for finding in by_rule.get("HETZ-GOV-004", []):
        label_names = _names(snapshot, finding.assets)
        add(92, f"Label {len(finding.assets)} servers with environment and role", finding.observation, finding, None, "low", None,
            "Add environment, role, and owner labels in IaC (sensitivity=high for databases and secrets) so policy and blast-radius checks cover every server.", ["HETZ-GOV-004"],
            commands=[f"hcloud server add-label {_shell_name(name)} environment=<env> role=<role> owner=<team>" for name in label_names[:12]])
    unlabeled = {asset for finding in by_rule.get("HETZ-GOV-004", []) for asset in finding.assets}
    for finding in by_rule.get("HETZ-GOV-002", []):
        if set(finding.assets) <= unlabeled:
            continue  # the GOV-004 action already asks for owner labels on these servers
        add(95, f"Add owner/project labels to {len(finding.assets)} servers", finding.observation, finding, None, "low", None,
            "Add owner, project, environment, and role labels through IaC.", ["HETZ-GOV-002"])
    # Rule families that map one finding to one action: (priority, category, risk of acting).
    generic = {
        "HETZ-FW-001": (11, "security", "low"),
        "HETZ-CERT-001": (12, "security", "low"),
        "HETZ-LB-006": (16, "security", "low"),
        "HETZ-LB-002": (18, "security", "low"),
        "HETZ-STO-001": (25, "security", "low"),
        "HETZ-DNS-001": (28, "security", "low"),
        "HETZ-STO-002": (35, "resilience", "low"),
        "HETZ-IMG-001": (38, "security", "medium"),
        "HETZ-LB-004": (45, "resilience", "low"),
        "HETZ-LB-001": (55, "cost", "low"),
        "HETZ-LB-003": (60, "security", "low"),
        "HETZ-LB-005": (70, "resilience", "medium"),
        "HETZ-PLC-001": (75, "resilience", "medium"),
        "HETZ-KEY-001": (65, "security", "low"),
        "HETZ-FW-003": (85, "security", "low"),
        "HETZ-KEY-002": (94, "hygiene", "low"),
        "HETZ-FW-002": (88, "hygiene", "low"),
        "HETZ-DNS-002": (90, "hygiene", "low"),
        "HETZ-CERT-002": (96, "hygiene", "low"),
        "HETZ-FW-004": (97, "hygiene", "low"),
        # Host evidence (--host-bundle)
        "HETZ-SSH-003": (2, "security", "low"),
        "HETZ-OBJ-001": (3, "security", "low"),
        "HETZ-OBJ-002": (4, "security", "low"),
        "HETZ-DKR-005": (6, "security", "low"),
        "HETZ-K8S-001": (7, "security", "medium"),
        "HETZ-ROB-001": (8, "security", "medium"),
        "HETZ-ROB-002": (9, "security", "low"),
        "HETZ-SSH-001": (13, "security", "low"),
        "HETZ-SSH-002": (14, "security", "low"),
        "HETZ-PG-003": (15, "security", "low"),
        "HETZ-HOST-002": (17, "security", "low"),
        "HETZ-ATT-001": (19, "security", "low"),
        "HETZ-ATT-004": (20, "security", "low"),
        "HETZ-DKR-006": (21, "security", "medium"),
        "HETZ-K8S-002": (22, "security", "medium"),
        "HETZ-ROB-005": (23, "security", "low"),
        "HETZ-CHG-004": (24, "security", "low"),
        "HETZ-HOST-001": (26, "security", "low"),
        "HETZ-XPR-001": (27, "security", "medium"),
        "HETZ-CHG-002": (29, "security", "low"),
        "HETZ-IAC-004": (30, "governance", "low"),
        "HETZ-EGR-001": (18, "security", "medium"),
        "HETZ-ROB-003": (31, "security", "medium"),
        "HETZ-ATT-003": (32, "security", "low"),
        "HETZ-ATT-002": (33, "security", "low"),
        "HETZ-CHG-001": (34, "resilience", "low"),
        "HETZ-OBJ-003": (36, "resilience", "low"),
        "HETZ-ATT-005": (37, "security", "low"),
        "HETZ-ATT-007": (39, "resilience", "low"),
        "HETZ-IAC-002": (86, "governance", "low"),
        "HETZ-IAC-003": (87, "governance", "low"),
        "HETZ-XPR-002": (89, "governance", "medium"),
        "HETZ-ATT-006": (91, "hygiene", "low"),
        "HETZ-CHG-003": (95, "hygiene", "low"),
        "HETZ-IAC-005": (98, "governance", "low"),
    }
    for rule_id, (priority, category, risk) in generic.items():
        group = by_rule.get(rule_id, [])
        if not group:
            continue
        first = group[0]
        fw_commands: list[str] = []
        if rule_id == "HETZ-FW-001":
            for fw_finding in group:
                observed: object = next((ev.observed for ev in fw_finding.evidence if ev.kind == "firewall_rule"), {})
                fw_rule: dict[str, Any] = observed if isinstance(observed, dict) else {}
                sources = " ".join(f"--source-ips {_shell_name(str(source))}" for source in (fw_rule.get("sources") or []))
                fw_name = _shell_name(_names(snapshot, fw_finding.assets[:1])[0])
                protocol = _shell_name(str(fw_rule.get("protocol", "tcp")))
                port_first, port_last = fw_rule.get("port_from"), fw_rule.get("port_to")
                port = (
                    "any" if port_first is None
                    else str(port_first) if port_first == port_last or port_last is None
                    else f"{port_first}-{port_last}"
                )
                fw_commands.append(
                    f"hcloud firewall delete-rule {fw_name} --direction in --protocol {protocol} --port {_shell_name(port)} {sources}".strip()
                )
        if len(group) == 1:
            add(priority, first.title, first.observation, first, None, risk, None, first.remediation, [rule_id], category, commands=fw_commands)
        else:  # one action per rule, not one per resource
            names = ", ".join(
                _names(snapshot, [item.assets[0] for item in group[:5] if item.assets]) or [item.title for item in group[:5]]
            ) + (" …" if len(group) > 5 else "")
            add(priority, f"{first.title} ({len(group)} resources)", f"Affected: {names}. {first.observation}", first, None, risk, None, first.remediation, [rule_id], category, commands=fw_commands)
    # Within the same priority band, stronger evidence first; a hypothesis never outranks a confirmed peer.
    strength = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    actions.sort(key=lambda item: (item["priority"] // 10, strength.get(item["evidence_level"], 3), item["priority"]))
    for index, item in enumerate(actions, 1):
        item["rank"] = index
    return actions


def _shell_name(value: str) -> str:
    """Provider names inside suggested commands: letters, digits, dot, dash, underscore, slash, colon only."""
    return re.sub(r"[^A-Za-z0-9._/:-]", "", value) or "<name>"


def _shell_safe(command: str) -> str:
    """One line, no code-fence breakout; names were already reduced by _shell_name."""
    return " ".join(command.split()).replace("`", "")


def render_actions_markdown(actions: list[dict[str, Any]], currency: str = "EUR") -> list[str]:
    lines = ["## Recommended actions", ""]
    if not actions:
        return lines + ["- No action is recommended from the collected evidence.", ""]
    for item in actions:
        saving = f"{currency} {item['saving_monthly']:.2f}/mo" if item["saving_monthly"] else "TBD"
        lines += [
            f"### {item['rank']}. {md(item['title'])}",
            "",
            f"**Saving:** {saving} · **Evidence:** {item['evidence_level']} ({md(item['evidence_reason'])}) · **Risk of acting:** {md(item['risk'])}",
            "",
            md(item["why"]),
            "",
            f"**Next step:** {md(item['next_step'])}",
            "",
        ]
        if item.get("commands"):
            lines += [
                "Suggested commands. Review them first: they need a Read & Write token, and hetzner-audit never runs them.",
                "",
                "```sh",
                *[_shell_safe(command) for command in item["commands"]],
                "```",
                "",
            ]
    return lines


def render_coverage_markdown(rows: list[tuple[str, int, str]], notes: list[str]) -> list[str]:
    lines = ["### What this audit knows", "", "| Coverage | | Basis |", "|---|---|---|"]
    lines += [f"| {name} | {percent}% | {md(basis)} |" for name, percent, basis in rows]
    lines += ["", *[f"- {md(note)}" for note in notes], ""]
    return lines
