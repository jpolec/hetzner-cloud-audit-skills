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
from ..cost import analyze_cost
from ..models import Asset, Finding, FindingStatus, Snapshot
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
                "assets": 0,
                "findings": 0,
                "evidence": evidence_level(finding),
            },
        )
        entry["assets"] += len(finding.assets)
        entry["findings"] += 1
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, None: 5}
    return sorted(groups.values(), key=lambda item: (order.get(item["severity"], 5), item["rule_id"]))


def build_summary(snapshot: Snapshot, findings: list[Finding]) -> dict[str, Any]:
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
        "missing_layers": missing_layers,
        "cost": cost,
    }


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
        (
            "Collection gaps",
            f"{_count(len(summary['failed_endpoints']), 'endpoint', 'endpoints')} failed · "
            f"{_count(len(summary['missing_layers']), 'evidence layer', 'evidence layers')} not collected"
            if gaps
            else "none",
        ),
    ]
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
            ("Confirmed savings", f"{currency} {cost['confirmed_monthly']:,.2f}/month (confirmation needs RAM, disk, owner intent, rollback)"),
        ]
    lines = ["## At a glance", "", "| | |", "|---|---|", *(f"| {name} | {md(value).replace(chr(92) + '`', '`')} |" for name, value in rows), ""]
    lines += render_coverage_markdown(summary.get("coverage", []), summary.get("provenance", []))
    lines += render_actions_markdown(summary.get("actions", []), cost["currency"] if cost else "EUR")
    lines += ["## Findings by status", "", "### Confirmed", ""]
    lines += [
        f"- **{(item['severity'] or 'unscored').upper()}** · {item['rule_id']} · {md(item['title'])}"
        + _affected(item)
        + f" · evidence {item['evidence'][0]}"
        for item in confirmed
    ] or ["- None."]
    lines += ["", "### Needs host or runtime validation", ""]
    lines += [
        f"- {item['rule_id']} · {md(item['title'])}" + _affected(item) + f" · evidence {item['evidence'][0]} ({item['evidence'][1]})"
        for item in pending
    ] or ["- None."]
    lines += ["", "### Collection gaps", ""]
    lines += [f"- Endpoint {md(name)}" for name in summary["failed_endpoints"]] or ["- Every Hetzner endpoint was collected."]
    lines += [
        f"- {name}: not collected. The Hetzner API cannot see it; related findings stay `needs_validation`."
        for name in summary["missing_layers"]
    ]
    if cost and not cost["metrics_collected"]:
        lines.append("- CPU metrics: not collected; run `hetzner-audit cost --metrics-days 30` for rightsizing candidates.")
    lines.append("")
    return lines
