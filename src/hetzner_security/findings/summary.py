"""First-page summary: scope, confirmed findings, hypotheses, collection gaps, and cost."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..actions import (
    build_actions,
    cost_insights,
    evidence_level,
    provenance,
    render_actions_markdown,
    render_coverage_markdown,
)
from ..actions import coverage as coverage_rows
from ..analyzers.changes import change_summary
from ..cost import analyze_cost
from ..models import Asset, Finding, FindingStatus, Snapshot
from ..projects import project_summary
from ..text import md

SCOPE_TYPES = (
    ("server", "server", "servers"),
    ("network", "network", "networks"),
    ("firewall", "firewall", "firewalls"),
    ("volume", "volume", "volumes"),
    ("load_balancer", "load balancer", "load balancers"),
    ("primary_ip", "primary IP", "primary IPs"),
    ("storage_box", "Storage Box", "Storage Boxes"),
)
# Evidence layers the Hetzner API cannot see; each needs host or service evidence.
RUNTIME_LAYERS: tuple[tuple[str, Callable[[Asset], bool]], ...] = (
    ("Host firewall", lambda asset: "host_firewall" in asset.properties or "host_firewall_allows_source" in asset.properties),
    ("Listeners and containers", lambda asset: asset.type == "container" or "listening_ports" in asset.properties or "listen_addresses" in asset.properties),
    ("PostgreSQL configuration (HBA, SSL)", lambda asset: asset.type == "postgres"),
    ("Redis configuration (ACL, bind)", lambda asset: asset.type == "redis"),
)


def _grouped(findings: list[Finding]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for finding in findings:
        key = (finding.rule_id, finding.title)
        entry = groups.setdefault(
            key,
            {
                "rule_id": finding.rule_id,
                "title": finding.title,
                "severity": finding.severity.value if finding.severity else None,
                "potential": finding.metadata.get("potential_severity"),
                "maturity": finding.metadata.get("rule_maturity", "fixture"),
                "assets": 0,
                "findings": 0,
                "evidence": evidence_level(finding),
            },
        )
        entry["assets"] += len(finding.assets)
        entry["findings"] += 1
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, None: 5}
    return sorted(groups.values(), key=lambda item: (order.get(item["severity"], 5), item["rule_id"]))


def build_summary(
    snapshot: Snapshot, findings: list[Finding], suppressed: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    counts = {kind: sum(1 for asset in snapshot.assets if asset.type == kind) for kind, _one, _many in SCOPE_TYPES}
    locations = {
        str(asset.properties.get("location", {}).get("name"))
        for asset in snapshot.assets
        if asset.type == "server" and isinstance(asset.properties.get("location"), dict)
    }
    coverage = snapshot.metadata.get("coverage", {})
    failed_endpoints = sorted(
        f"{name} ({state.get('status')})"
        for name, state in (coverage.items() if isinstance(coverage, dict) else [])
        if isinstance(state, dict) and state.get("status") not in {"collected", None}
    )
    missing_layers = [name for name, present in RUNTIME_LAYERS if not any(present(asset) for asset in snapshot.assets)]
    cost: dict[str, Any] | None = None
    report: dict[str, Any] | None = None
    if any(asset.type == "pricing" for asset in snapshot.assets):
        report = analyze_cost(snapshot)
        servers = report.get("servers", [])
        cost = {
            "currency": report.get("currency", "EUR"),
            "monthly": report["current_catalog_estimate"]["monthly_net"],
            "potential_monthly": report["identified_potential_savings"]["monthly_net"],
            "potential_annual": report["identified_potential_savings"]["annual_net"],
            "confirmed_monthly": report["identified_potential_savings"]["confirmed_monthly_net"],
            "expected_monthly": report["identified_potential_savings"].get("expected_monthly_net", 0.0),
            "measured_monthly": report["identified_potential_savings"].get("measured_monthly_net", 0.0),
            "metrics_collected": any(item.get("cpu_samples") for item in servers),
            **{key: value for key, value in cost_insights(report).items() if key not in {"waste", "storage_heavy"}},
        }
    return {
        "actions": build_actions(snapshot, findings, report),
        "coverage": coverage_rows(snapshot, report),
        "provenance": provenance(snapshot, report),
        "scope": {kind: count for kind, count in counts.items() if count},
        "locations": sorted(locations),
        "confirmed": _grouped([item for item in findings if item.status == FindingStatus.CONFIRMED]),
        "needs_validation": _grouped([item for item in findings if item.status == FindingStatus.NEEDS_VALIDATION]),
        "rejected": sum(1 for item in findings if item.status == FindingStatus.REJECTED),
        "failed_endpoints": failed_endpoints,
        "suppressed": suppressed or [],
        "missing_layers": missing_layers,
        "host_evidence": host_rows(snapshot),
        "ingress": _ingress_summary(snapshot),
        "egress": _egress_summary(snapshot),
        "other_sources": other_sources(snapshot),
        "cost": cost,
        "changes": change_summary(snapshot) if any(str(key).endswith("actions") for key in coverage) else None,
        "projects": project_summary(snapshot) if snapshot.metadata.get("projects") else [],
    }


def _egress_summary(snapshot: Snapshot) -> dict[str, Any]:
    from ..analyzers.egress import SENSITIVE_ROLES
    from ..flows import egress_summary

    servers = [asset for asset in snapshot.assets if asset.type == "server" and asset.properties.get("public_ip", True)]
    open_servers = [asset for asset in servers if egress_summary(asset)["state"] == "unrestricted"]
    return {
        "servers": len(servers),
        "unrestricted": len(open_servers),
        "sensitive_unrestricted": sorted(asset.name for asset in open_servers if asset.labels.get("role", "").lower() in SENSITIVE_ROLES),
    }


def _ingress_summary(snapshot: Snapshot) -> dict[str, Any]:
    """The good pattern, named explicitly: servers that accept nothing from the Internet."""
    from ..topology import build_topology

    topology = build_topology(snapshot)
    servers = [item for item in topology["servers"] if item["public_ip"]]
    return {
        "servers": len(servers),
        "no_public_ingress": sum(1 for item in servers if item["no_public_ingress"]),
        "tunnels": sorted({name for item in topology["servers"] for name in item["tunnels"]}),
        "edge_providers": topology.get("edge_providers") or [],
    }


def host_rows(snapshot: Snapshot) -> list[dict[str, Any]]:
    """Per server with a host bundle: what each layer admits and what is reachable end to end."""
    from ..analyzers.host import _cloud_world
    from ..flows import PortSet, port_set

    rows = []
    for asset in snapshot.assets:
        props = asset.properties
        if asset.type != "server" or not props.get("host_evidence"):
            continue
        firewall = props.get("host_firewall") or {}
        cloud = _cloud_world(asset, snapshot, "tcp")
        listening = PortSet.of([(port, port) for port in props.get("listening_ports") or []])
        host_allowed = port_set(props.get("host_firewall_allow_ports"))
        own_rules = port_set(firewall.get("world_tcp_ranges"))
        bypass = sorted({item["host_port"] for item in props.get("docker_published") or []
                         if item.get("bind") in {"wildcard", "public"} and item.get("protocol") == "tcp" and item["host_port"] not in own_rules})
        known_fw = bool(firewall.get("known", True)) and props.get("host_firewall_allow_ports") is not None
        known_listeners = props.get("listening_ports") is not None
        if not known_fw:
            engine = f"{firewall.get('engine') or 'unknown'} (unreadable)"
        else:
            engine = f"{firewall.get('engine')}" + ("" if firewall.get("active") else " (filters nothing)")
        rows.append({
            "name": asset.name,
            "engine": engine,
            "known": known_fw and known_listeners,
            "host_firewall_admits": (firewall.get("world_tcp") or "nothing") if known_fw else "unknown",
            "public_listeners": (listening.describe() or "none") if known_listeners else "unknown",
            "docker_bypass": bypass,
            "cloud_admits": cloud.describe() or "nothing",
            "reachable": (cloud.intersection(host_allowed).intersection(listening).describe() or "none")
            if known_fw and known_listeners else "unknown",
            # Cloud Firewalls never filter private networks: host firewall and listeners decide alone.
            "private_reachable": (
                (PortSet.of([(port, port) for port in props.get("private_listening_ports") or []])
                 .intersection(port_set(props.get("host_firewall_private_allow_ports"))).describe() or "none")
                if props.get("host_firewall_private_allow_ports") is not None and props.get("private_listening_ports") is not None
                else "unknown"
            ) if props.get("private_net") else None,
            "containers": sum(1 for other in snapshot.assets if other.type == "container" and other.properties.get("server") == asset.id),
        })
    return rows


def other_sources(snapshot: Snapshot) -> list[str]:
    """One line per optional evidence source that was supplied."""
    meta = snapshot.metadata
    of = [asset for asset in snapshot.assets]
    lines = []
    robot = [asset for asset in of if asset.type == "robot_server"]
    if robot:
        active = sum(1 for asset in robot if (asset.properties.get("robot_firewall") or {}).get("status") == "active")
        vswitches = sum(1 for asset in of if asset.type == "vswitch")
        lines.append(f"Robot: {len(robot)} dedicated server(s), Robot firewall active on {active}; {vswitches} vSwitch(es).")
    buckets = [asset for asset in of if asset.type == "bucket"]
    if buckets:
        from ..collectors.objectstorage import public_grants, public_statements

        public = sum(1 for asset in buckets if public_grants(asset.properties) or public_statements(asset.properties))
        versioned = sum(1 for asset in buckets if asset.properties.get("versioning") == "Enabled")
        lines.append(f"Object Storage: {len(buckets)} bucket(s), {public} with public access, {versioned} versioned.")
    k8s = meta.get("kubernetes")
    if k8s:
        workloads = sum(1 for asset in of if asset.type == "k8s_workload")
        services = sum(1 for asset in of if asset.type == "k8s_service")
        lines.append(
            f"Kubernetes ({k8s['cluster']}): {len(k8s['matched_nodes'])}/{k8s['nodes']} node(s) matched to servers; "
            f"{workloads} workload(s) with node-level access; {services} NodePort/LoadBalancer service(s); "
            f"integrations: {', '.join(k8s['integrations']) or 'none detected'}."
        )
    terraform = meta.get("terraform")
    if terraform:
        lines.append(
            f"Terraform ({terraform['kind']}): {len(terraform['managed'])} resource(s) matched; {len(terraform['unmanaged'])} not in state; "
            f"{len(terraform['missing'])} in state but gone; {len(terraform['attribute_drift'])} with drifted settings; "
            f"{len(terraform['pending_changes'])} pending plan change(s)."
        )
    attestations = meta.get("attestations")
    if attestations:
        answers = list((attestations.get("answers") or {}).values())
        lines.append(
            f"Owner checklist: {sum(1 for value in answers if value is True)} yes · {sum(1 for value in answers if value is False)} no · "
            f"{sum(1 for value in answers if value not in (True, False))} not verified"
            + (f" (answered by {attestations['answered_by']}, {attestations.get('date') or 'undated'})" if attestations.get("answered_by") else "")
            + "."
        )
    metrics = meta.get("node_metrics")
    if metrics:
        lines.append(f"Guest telemetry: {len(metrics['matched'])} server(s) matched" + (f"; unmatched hosts: {', '.join(metrics['unmatched'])}" if metrics["unmatched"] else "") + ".")
    unmatched = [item["server"] for item in meta.get("host_bundles") or [] if item.get("status") == "unmatched"]
    if unmatched:
        lines.append(f"Host bundles not matched to any server: {', '.join(unmatched)} (set HETZNER_AUDIT_SERVER to the Hetzner server name).")
    return lines


def _count(value: int, one: str, many: str) -> str:
    return f"{value} {one if value == 1 else many}"


def _affected(item: dict[str, Any]) -> str:
    # Path findings list source and target, not affected assets; show counts only for affected-asset groups.
    if item["findings"] > 1 or item["rule_id"].startswith("HETZ-GOV-"):
        return f" ({_count(item['assets'], 'asset', 'assets')})" if item["assets"] > 1 else ""
    return ""


def render_summary_markdown(summary: dict[str, Any]) -> list[str]:
    labels = {kind: (one, many) for kind, one, many in SCOPE_TYPES}
    scope = " · ".join(
        f"{count} {labels[kind][0] if count == 1 else labels[kind][1]}" for kind, count in summary["scope"].items()
    ) or "no assets"
    if summary["locations"]:
        scope += f" · {len(summary['locations'])} location{'s' if len(summary['locations']) != 1 else ''} ({', '.join(summary['locations'])})"
    confirmed = summary["confirmed"]
    pending = summary["needs_validation"]
    gaps = len(summary["failed_endpoints"]) + len(summary["missing_layers"])
    rows = [
        ("Scope", scope),
        ("Confirmed (evidence complete)", _count(sum(item["findings"] for item in confirmed), "finding", "findings")),
        ("Needs host/runtime validation", _count(sum(item["findings"] for item in pending), "hypothesis", "hypotheses")),
        ("Rejected by the verifier", str(summary["rejected"])),
        ("Suppressed by owner labels", str(len(summary.get("suppressed", [])))),
        (
            "Collection gaps",
            f"{_count(len(summary['failed_endpoints']), 'endpoint', 'endpoints')} failed · "
            f"{_count(len(summary['missing_layers']), 'evidence layer', 'evidence layers')} not collected"
            if gaps
            else "none",
        ),
    ]
    if summary.get("projects"):
        rows.insert(1, ("Projects", " · ".join(
            f"{item['project']} ({item['assets'].get('server', 0)} servers)" for item in summary["projects"]
        )))
    ingress = summary.get("ingress")
    if ingress and ingress["servers"]:
        rows.append((
            "No public ingress",
            f"{ingress['no_public_ingress']} of {ingress['servers']} servers accept nothing from the Internet"
            + (f" · tunnel agents: {', '.join(ingress['tunnels'])}" if ingress["tunnels"] else "")
            + (f" · edge proxies: {', '.join(ingress['edge_providers'])}" if ingress["edge_providers"] else ""),
        ))
    egress = summary.get("egress")
    if egress and egress["servers"]:
        rows.append((
            "Internet egress",
            f"{egress['unrestricted']} of {egress['servers']} public servers may connect anywhere (no outbound firewall rule)"
            + (f" · including data/identity hosts: {', '.join(egress['sensitive_unrestricted'][:5])}" if egress["sensitive_unrestricted"] else "")
            + " · limit it per role with internet_egress in the policy's roles section",
        ))
    changes = summary.get("changes")
    if changes:
        top = ", ".join(f"{command} {count}" for command, count in list(changes["by_command"].items())[:4])
        rows.append((f"Provider changes ({changes['window_days']} days)", f"{changes['total']} actions" + (f" · {top}" if top else "")))
    cost = summary.get("cost")
    if cost:
        currency = cost["currency"]
        rows += [
            ("Estimated catalog cost", f"{currency} {cost['monthly']:,.2f}/month · top 3 VMs = {cost.get('top3_share', 0):.0%}, top 5 = {cost.get('top5_share', 0):.0%}"),
            ("Immediately identifiable waste", f"{currency} {cost.get('waste_monthly', 0):,.2f}/month (unused resources, no telemetry needed)"),
            (
                "Optimization opportunities",
                (
                    f"{_count(cost.get('opportunities', 0), 'candidate', 'candidates')} need RAM/disk telemetry"
                    + (f" (up to {currency} {cost.get('opportunities_monthly', 0):,.2f}/month)" if cost.get("opportunities") else "")
                )
                if cost["metrics_collected"]
                else "not evaluated: CPU metrics not collected (run `hetzner-audit cost --metrics-days 30`)",
            ),
            ("Savings: theoretical · expected · measured",
             f"{currency} {cost['potential_monthly']:,.2f} · {cost.get('expected_monthly', 0):,.2f} · {cost.get('measured_monthly', 0):,.2f} per month "
             "(expected = unused resources plus rightsizing with full CPU/RAM/disk telemetry; measured = catalog delta from `diff` "
             "after a change, priced at the earlier catalog; invoices are not reconciled)"),
        ]
    lines = ["## At a glance", "", "| | |", "|---|---|", *(f"| {name} | {md(value).replace(chr(92) + '`', '`')} |" for name, value in rows), ""]
    lines += render_coverage_markdown(summary.get("coverage", []), summary.get("provenance", []))
    if summary.get("host_evidence") or summary.get("other_sources"):
        lines += ["### Evidence beyond the Cloud API", ""]
        if summary.get("host_evidence"):
            lines += ["| Server | Host firewall | Admits from Internet | Public listeners | Docker bypass | Cloud Firewall admits | Reachable from Internet | Reachable from private network |",
                      "|---|---|---|---|---|---|---|---|"]
            lines += [
                f"| {md(row['name'])} | {md(str(row['engine']))} | {md(row['host_firewall_admits'])} | {md(row['public_listeners'])} | "
                f"{', '.join(map(str, row['docker_bypass'])) or 'none'} | {md(row['cloud_admits'])} | **{md(row['reachable'])}** | "
                f"{md(row['private_reachable']) if row['private_reachable'] is not None else 'not in a network'} |"
                for row in summary["host_evidence"]
            ]
            lines.append("")
        lines += [f"- {md(line)}" for line in summary.get("other_sources", [])]
        lines.append("")
    lines += render_actions_markdown(summary.get("actions", []), cost["currency"] if cost else "EUR")
    lines += ["## Findings by status", "", "### Confirmed", ""]
    lines += [
        f"- **{(item['severity'] or 'unscored').upper()}** · {item['rule_id']} · {md(item['title'])}"
        + _affected(item)
        + f" · evidence {item['evidence'][0]}"
        + (" · rule tested on fixtures only" if item.get("maturity") == "fixture" else "")
        for item in confirmed
    ] or ["- None."]
    lines += ["", "### Needs host or runtime validation", ""]
    lines += [
        f"- {(('potential ' + item['potential'].upper() + ' · ') if item.get('potential') else '')}{item['rule_id']} · {md(item['title'])}" + _affected(item) + f" · evidence {item['evidence'][0]} ({item['evidence'][1]})"
        + (" · rule tested on fixtures only" if item.get("maturity") == "fixture" else "")
        for item in pending
    ] or ["- None."]
    lines += ["", "### Collection gaps", ""]
    lines += [f"- Endpoint {md(name)}" for name in summary["failed_endpoints"]] or ["- Every Hetzner endpoint was collected."]
    lines += [
        f"- {name}: not collected. The Hetzner API cannot see it; related findings stay `needs_validation` "
        "until you add `--host-bundle` (see `hetzner-audit host-bundle`)."
        for name in summary["missing_layers"]
    ]
    if summary.get("suppressed"):
        lines += ["", "### Suppressed by owner labels (`audit.ignore`)", ""]
        lines += [f"- {item['rule_id']} · {md(item['title'])} ({len(item['assets'])} asset(s))" for item in summary["suppressed"]]
    if cost and not cost["metrics_collected"]:
        lines.append("- CPU metrics: not collected; run `hetzner-audit cost --metrics-days 30` for rightsizing candidates.")
    lines.append("")
    return lines
