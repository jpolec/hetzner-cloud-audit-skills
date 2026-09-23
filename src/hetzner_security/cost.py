"""Evidence-backed Hetzner catalog-cost analysis.

Savings are candidates, never provider actions. Missing guest RAM keeps every resize or
architecture migration in ``needs_validation``.
"""

from __future__ import annotations

import hashlib
import math
from datetime import UTC, datetime
from typing import Any

from .models import Asset, Snapshot


def _price(prices: object, location: str) -> float | None:
    if not isinstance(prices, list):
        return None
    for item in prices:
        if not isinstance(item, dict) or item.get("location") != location:
            continue
        monthly = item.get("price_monthly", {})
        if isinstance(monthly, dict) and monthly.get("net") is not None:
            return float(monthly["net"])
    return None


def _values(metrics: object, key: str) -> list[float]:
    if not isinstance(metrics, dict):
        return []
    series = metrics.get("time_series", {})
    if not isinstance(series, dict):
        return []
    item = series.get(key, {})
    if not isinstance(item, dict):
        return []
    output = []
    for point in item.get("values", []):
        try:
            output.append(float(point[1]))
        except (IndexError, TypeError, ValueError):
            continue
    return output


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * fraction) - 1))
    return ordered[index]


def _id(rule_id: str, asset_id: str, candidate: str) -> str:
    digest = hashlib.sha256(f"{rule_id}\x00{asset_id}\x00{candidate}".encode()).hexdigest()[:16]
    return f"{rule_id}-{digest}"


def _location(server: Asset) -> str:
    location = server.properties.get("location", {})
    return str(location.get("name", "")) if isinstance(location, dict) else str(location)


def _available(server_type: Asset, location: str) -> bool:
    locations = server_type.properties.get("locations", [])
    if not isinstance(locations, list) or not locations:
        return True
    return any(
        isinstance(item, dict) and item.get("name") == location and item.get("available") is True
        for item in locations
    )


def analyze_cost(snapshot: Snapshot) -> dict[str, Any]:
    assets = snapshot.assets
    servers = [asset for asset in assets if asset.type == "server"]
    volumes = [asset for asset in assets if asset.type == "volume"]
    primary_ips = [asset for asset in assets if asset.type == "primary_ip"]
    floating_ips = [asset for asset in assets if asset.type == "floating_ip"]
    snapshots = [asset for asset in assets if asset.type == "snapshot"]
    load_balancers = [asset for asset in assets if asset.type == "load_balancer"]
    storage_boxes = [asset for asset in assets if asset.type == "storage_box"]
    server_types = [asset for asset in assets if asset.type == "server_type"]
    pricing_asset = next((asset for asset in assets if asset.type == "pricing"), None)
    pricing = pricing_asset.properties if pricing_asset else {}
    observed_at = str(snapshot.metadata.get("collected_at") or datetime.now(UTC).isoformat())
    metrics_coverage = (snapshot.metadata.get("coverage") or {}).get("server_metrics") or {}
    requested_days = metrics_coverage.get("window_days") if isinstance(metrics_coverage, dict) else None
    telemetry_gaps: list[str] = []

    volume_rate = _nested_float(pricing, "volume", "price_per_gb_month", "net")
    backup_pct = _nested_float(pricing, "server_backup", "percentage") / 100.0
    ipv4_prices = _ipv4_prices(pricing)
    floating_prices = _resource_prices(pricing.get("floating_ips", []), "ipv4")
    volumes_by_server = _group_by_numeric(volumes, "server")
    ips_by_server = _group_by_numeric(primary_ips, "assignee_id")

    server_rows: list[dict[str, Any]] = []
    recommendations: list[dict[str, Any]] = []
    for server in servers:
        props = server.properties
        server_id = props.get("id")
        location = _location(server)
        current_type = props.get("server_type", {})
        current_type = current_type if isinstance(current_type, dict) else {}
        base = _price(current_type.get("prices"), location) or 0.0
        server_volumes = volumes_by_server.get(server_id, [])
        volume_cost = sum(float(v.properties.get("size", 0)) * volume_rate for v in server_volumes)
        ipv4_count = sum(1 for ip in ips_by_server.get(server_id, []) if ip.properties.get("type") == "ipv4")
        ipv4_cost = ipv4_count * ipv4_prices.get(location, 0.0)
        backup_cost = base * backup_pct if props.get("backup_enabled") else 0.0
        monthly = base + volume_cost + ipv4_cost + backup_cost

        cpu = _values(props.get("metrics", {}), "cpu")
        cpu_p95_raw = _percentile(cpu, 0.95)
        cpu_max_raw = max(cpu) if cpu else None
        cores = int(current_type.get("cores", 0) or 0)
        cpu_p95_capacity = cpu_p95_raw / cores if cpu_p95_raw is not None and cores else None
        cpu_max_capacity = cpu_max_raw / cores if cpu_max_raw is not None and cores else None
        row = {
            "asset_id": server.id,
            "name": server.name,
            "status": props.get("status"),
            "server_type": current_type.get("name"),
            "architecture": current_type.get("architecture"),
            "cores": cores,
            "memory_gb": current_type.get("memory"),
            "monthly_net": round(monthly, 2),
            "components_net": {
                "server": round(base, 2),
                "volumes": round(volume_cost, 2),
                "ipv4": round(ipv4_cost, 2),
                "backup": round(backup_cost, 2),
            },
            "cpu_samples": len(cpu),
            "cpu_p95_capacity_percent": round(cpu_p95_capacity, 2) if cpu_p95_capacity is not None else None,
            "cpu_max_capacity_percent": round(cpu_max_capacity, 2) if cpu_max_capacity is not None else None,
            "metrics_start": props.get("metrics", {}).get("start") if isinstance(props.get("metrics"), dict) else None,
            "metrics_end": props.get("metrics", {}).get("end") if isinstance(props.get("metrics"), dict) else None,
        }
        server_rows.append(row)

        if props.get("status") != "running" and monthly > 0:
            recommendations.append(
                _recommendation(
                    "HETZ-COST-001",
                    server,
                    "Validate retirement of a stopped but billed server",
                    row,
                    {"action": "retire after owner, dependency, and restore validation"},
                    monthly,
                    observed_at,
                    "medium",
                    0.9,
                    ["Owner confirms the server is not a rollback or cold-standby asset.", "Required data and restore points are preserved."],
                    ["Stopped servers remain billable while they exist."],
                )
            )
            continue

        if cpu_p95_capacity is None or cpu_p95_capacity >= 30 or base <= 0:
            continue
        window = _observation_window(server_rows[-1], observed_at) if server_rows else {}
        if isinstance(requested_days, (int, float)) and requested_days > 0 and (window.get("days") or 0) < 0.8 * requested_days:
            # Too little telemetry: a low p95 over a few hours says nothing about a monthly peak.
            telemetry_gaps.append(
                f"{server.name}: CPU data covers {window.get('days') or 0} of {requested_days} requested days; no rightsizing candidate"
            )
            continue
        same_arch = _best_resize_candidate(
            server, server_types, cpu_p95_raw, cpu_max_raw, location, base
        )
        if same_arch is not None:
            candidate, candidate_price = same_arch
            saving = base - candidate_price
            recommendations.append(
                _recommendation(
                    "HETZ-COST-002",
                    server,
                    "Validate compute rightsizing",
                    row,
                    _candidate_state(candidate, candidate_price),
                    saving,
                    observed_at,
                    "medium",
                    0.72,
                    ["Collect guest RAM p95.", "Validate root filesystem usage, I/O peaks, SLO, and migration path."],
                    [f"30-day CPU p95 uses {cpu_p95_capacity:.2f}% of aggregate vCPU capacity."],
                )
            )
        if current_type.get("architecture") == "x86":
            arm = _best_arm_candidate(server, server_types, location, base)
            if arm is not None:
                candidate, candidate_price = arm
                recommendations.append(
                    _recommendation(
                        "HETZ-COST-003",
                        server,
                        "Validate x86-to-ARM migration",
                        row,
                        _candidate_state(candidate, candidate_price),
                        base - candidate_price,
                        observed_at,
                        "medium",
                        0.62,
                        ["Prove multi-architecture image and native dependency support.", "Benchmark representative load and retain rollback."],
                        [f"A same-capacity ARM catalog type is cheaper in {location}."],
                    )
                )

    orphan_volume_cost = 0.0
    for volume in volumes:
        if volume.properties.get("server") is not None:
            continue
        monthly = float(volume.properties.get("size", 0)) * volume_rate
        orphan_volume_cost += monthly
        if monthly > 0:
            recommendations.append(
                _recommendation(
                    "HETZ-COST-004",
                    volume,
                    "Validate retirement of an unattached volume",
                    {"server_type": f"{volume.properties.get('size', 0)} GB volume", "monthly_net": round(monthly, 2)},
                    {"action": "delete only after ownership, IaC, and recovery validation"},
                    monthly,
                    observed_at,
                    "medium",
                    0.9,
                    ["Confirm no attachment, IaC owner, restore dependency, or pending migration."],
                    ["Provider inventory reports no attached server."],
                )
            )

    orphan_primary_ip_cost = 0.0
    for address in primary_ips:
        if address.properties.get("assignee_id") is not None or address.properties.get("type") != "ipv4":
            continue
        location = address.properties.get("datacenter", {}).get("location", {}).get("name")
        location = location or address.properties.get("location", {}).get("name")
        monthly = ipv4_prices.get(str(location), next(iter(ipv4_prices.values()), 0.0))
        orphan_primary_ip_cost += monthly
        if monthly > 0:
            recommendations.append(
                _recommendation(
                    "HETZ-COST-005",
                    address,
                    "Validate release of an unassigned Primary IPv4",
                    {"server_type": "unassigned Primary IPv4", "monthly_net": round(monthly, 2)},
                    {"action": "release only after DNS, IaC, and reservation validation"},
                    monthly,
                    observed_at,
                    "low",
                    0.92,
                    ["Confirm the address is not reserved for failover, migration, DNS, or allowlists."],
                    ["Provider inventory reports no assignee."],
                )
            )

    floating_ip_cost = 0.0
    for address in floating_ips:
        location = address.properties.get("home_location", {}).get("name", "")
        monthly = floating_prices.get(str(location), next(iter(floating_prices.values()), 0.0))
        floating_ip_cost += monthly
        if address.properties.get("server") is None and monthly > 0:
            recommendations.append(
                _recommendation(
                    "HETZ-COST-006",
                    address,
                    "Validate release of an unassigned Floating IP",
                    {"server_type": "unassigned Floating IP", "monthly_net": round(monthly, 2)},
                    {"action": "release only after failover, DNS, and IaC validation"},
                    monthly,
                    observed_at,
                    "low",
                    0.9,
                    ["Confirm the address is not retained for failover or migration."],
                    ["Provider inventory reports no assigned server."],
                )
            )

    image_rate = _nested_float(pricing, "image", "price_per_gb_month", "net")
    snapshot_cost = 0.0
    observed_datetime = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    for snapshot_asset in snapshots:
        monthly = float(snapshot_asset.properties.get("image_size", 0) or 0) * image_rate
        snapshot_cost += monthly
        created = snapshot_asset.properties.get("created")
        try:
            age_days = (observed_datetime - datetime.fromisoformat(str(created).replace("Z", "+00:00"))).days
        except (TypeError, ValueError):
            age_days = 0
        if age_days >= 90 and monthly > 0:
            recommendations.append(
                _recommendation(
                    "HETZ-COST-007",
                    snapshot_asset,
                    "Validate retention of a stale snapshot",
                    {"server_type": f"snapshot aged {age_days} days", "monthly_net": round(monthly, 2)},
                    {"action": "expire only after retention and restore validation"},
                    monthly,
                    observed_at,
                    "medium",
                    0.75,
                    ["Confirm legal, rollback, recovery, and IaC retention requirements."],
                    [f"Snapshot age is {age_days} days."],
                )
            )

    load_balancer_cost = sum(_load_balancer_monthly(asset) for asset in load_balancers)
    storage_box_cost = sum(_storage_box_monthly(asset) for asset in storage_boxes)
    other_resource_monthly = (
        orphan_volume_cost
        + orphan_primary_ip_cost
        + floating_ip_cost
        + snapshot_cost
        + load_balancer_cost
        + storage_box_cost
    )
    current_monthly = sum(row["monthly_net"] for row in server_rows) + other_resource_monthly
    selected: dict[str, float] = {}
    for recommendation in recommendations:
        asset_id = recommendation["assets"][0]
        selected[asset_id] = max(selected.get(asset_id, 0.0), recommendation["estimated_savings"]["monthly"])
    potential_monthly = sum(selected.values())
    return {
        "schema_version": "1.0.0",
        "status": "needs_validation" if recommendations else "confirmed",
        "currency": str(pricing.get("currency", "EUR")),
        "price_observed_at": observed_at,
        "current_catalog_estimate": {
            "monthly_net": round(current_monthly, 2),
            "annual_net": round(current_monthly * 12, 2),
            "basis": "Current Hetzner catalog prices; not an invoice.",
        },
        "identified_potential_savings": {
            "monthly_net": round(potential_monthly, 2),
            "annual_net": round(potential_monthly * 12, 2),
            "confirmed_monthly_net": 0.0,
            "basis": "Maximum non-overlapping candidate per asset; all require validation.",
        },
        "servers": server_rows,
        "resource_components_net": {
            "unattached_volumes": round(orphan_volume_cost, 2),
            "unassigned_primary_ipv4": round(orphan_primary_ip_cost, 2),
            "floating_ips": round(floating_ip_cost, 2),
            "snapshots": round(snapshot_cost, 2),
            "load_balancers": round(load_balancer_cost, 2),
            "storage_boxes": round(storage_box_cost, 2),
        },
        "recommendations": recommendations,
        "data_gaps": [
            "Hetzner does not expose guest RAM utilization.",
            "Filesystem occupancy, workload SLOs, and application architecture constraints are not provider metrics.",
            "Catalog prices can differ from invoices, credits, taxes, and legacy contracts.",
            *telemetry_gaps,
        ],
    }


def _nested_float(value: dict[str, Any], *keys: str) -> float:
    current: Any = value
    for key in keys:
        if not isinstance(current, dict):
            return 0.0
        current = current.get(key)
    try:
        return float(current)
    except (TypeError, ValueError):
        return 0.0


def _ipv4_prices(pricing: dict[str, Any]) -> dict[str, float]:
    output: dict[str, float] = {}
    values = pricing.get("primary_ips", [])
    if not isinstance(values, list):
        return output
    for item in values:
        if not isinstance(item, dict) or item.get("type") != "ipv4":
            continue
        for price in item.get("prices", []):
            if isinstance(price, dict):
                monthly = price.get("price_monthly", {})
                if isinstance(monthly, dict) and monthly.get("net") is not None:
                    output[str(price.get("location"))] = float(monthly["net"])
    return output


def _resource_prices(values: object, resource_type: str) -> dict[str, float]:
    output: dict[str, float] = {}
    if not isinstance(values, list):
        return output
    for item in values:
        if not isinstance(item, dict) or item.get("type") != resource_type:
            continue
        for price in item.get("prices", []):
            if not isinstance(price, dict):
                continue
            monthly = price.get("price_monthly", {})
            if isinstance(monthly, dict) and monthly.get("net") is not None:
                output[str(price.get("location"))] = float(monthly["net"])
    return output


def _group_by_numeric(assets: list[Asset], key: str) -> dict[object, list[Asset]]:
    output: dict[object, list[Asset]] = {}
    for asset in assets:
        output.setdefault(asset.properties.get(key), []).append(asset)
    return output


def _type_price(asset: Asset, location: str) -> float | None:
    return _price(asset.properties.get("prices"), location)


def _best_resize_candidate(
    server: Asset,
    server_types: list[Asset],
    cpu_p95_raw: float | None,
    cpu_max_raw: float | None,
    location: str,
    current_price: float,
) -> tuple[Asset, float] | None:
    current = server.properties.get("server_type", {})
    if not isinstance(current, dict):
        return None
    cores = int(current.get("cores", 0) or 0)
    memory = float(current.get("memory", 0) or 0)
    candidates = []
    for item in server_types:
        props = item.properties
        price = _type_price(item, location)
        item_cores = int(props.get("cores", 0) or 0)
        if (
            price is None
            or price >= current_price
            or props.get("deprecated") is True
            or props.get("architecture") != current.get("architecture")
            or props.get("cpu_type") != current.get("cpu_type")
            or item_cores < max(1, math.ceil(cores / 2))
            or float(props.get("memory", 0) or 0) < memory / 2
            or not _available(item, location)
        ):
            continue
        projected = cpu_p95_raw / item_cores if cpu_p95_raw is not None and item_cores else 100.0
        projected_max = cpu_max_raw / item_cores if cpu_max_raw is not None and item_cores else 100.0
        if projected < 60 and projected_max < 80:
            candidates.append((price, item))
    if not candidates:
        return None
    price, item = min(candidates, key=lambda value: value[0])
    return item, price


def _best_arm_candidate(
    server: Asset, server_types: list[Asset], location: str, current_price: float
) -> tuple[Asset, float] | None:
    current = server.properties.get("server_type", {})
    if not isinstance(current, dict):
        return None
    candidates = []
    for item in server_types:
        props = item.properties
        price = _type_price(item, location)
        if (
            price is None
            or price >= current_price
            or props.get("architecture") != "arm"
            or props.get("deprecated") is True
            or int(props.get("cores", 0) or 0) < int(current.get("cores", 0) or 0)
            or float(props.get("memory", 0) or 0) < float(current.get("memory", 0) or 0)
            or not _available(item, location)
        ):
            continue
        candidates.append((price, item))
    if not candidates:
        return None
    price, item = min(candidates, key=lambda value: value[0])
    return item, price


def _observation_window(current: dict[str, Any], observed_at: str) -> dict[str, Any]:
    """The window actually covered by samples, not the requested one."""
    start, end = current.get("metrics_start") or observed_at, current.get("metrics_end") or observed_at
    days: float | None = None
    try:
        span = datetime.fromisoformat(str(end).replace("Z", "+00:00")) - datetime.fromisoformat(str(start).replace("Z", "+00:00"))
        days = round(span.total_seconds() / 86400, 1) or None  # unknown rather than a fake zero
    except ValueError:
        pass
    return {"start": start, "end": end, "days": days, "samples": current.get("cpu_samples", 0)}


def _candidate_state(candidate: Asset, price: float) -> dict[str, Any]:
    props = candidate.properties
    return {
        "server_type": props.get("name", candidate.name),
        "architecture": props.get("architecture"),
        "cores": props.get("cores"),
        "memory_gb": props.get("memory"),
        "compute_monthly_net": round(price, 2),
    }


def _recommendation(
    rule_id: str,
    server: Asset,
    title: str,
    current: dict[str, Any],
    candidate: dict[str, Any],
    monthly_saving: float,
    observed_at: str,
    risk: str,
    confidence: float,
    prerequisites: list[str],
    evidence: list[str],
) -> dict[str, Any]:
    candidate_name = str(candidate.get("server_type", candidate.get("action", "candidate")))
    return {
        "id": _id(rule_id, server.id, candidate_name),
        "rule_id": rule_id,
        "title": title,
        "provider": "hetzner",
        "status": "needs_validation",
        "assets": [server.id],
        "observation_window": _observation_window(current, observed_at),
        "current_state": current,
        "metrics": [
            {
                "name": "cpu_capacity",
                "statistic": "p95",
                "value": float(current["cpu_p95_capacity_percent"]),
                "unit": "percent",
                "source": "hcloud_metrics",
                "collected_at": observed_at,
            }
        ] if current.get("cpu_p95_capacity_percent") is not None else [],
        "data_gaps": ["guest RAM p95", "filesystem occupancy", "workload SLO and seasonality"],
        "candidate_state": candidate,
        "estimated_savings": {
            "monthly": round(max(0.0, monthly_saving), 2),
            "annual": round(max(0.0, monthly_saving) * 12, 2),
            "currency": "EUR",
            "basis": "Current catalog price; excludes tax, credits, traffic, and migration cost.",
            "price_observed_at": observed_at,
        },
        "risk": risk,
        "confidence": confidence,
        "prerequisites": prerequisites,
        "evidence": [{"source": "cost_analyzer", "observation": item} for item in evidence],
        "cross_domain_impacts": {
            "security": ["Preserve or improve current network trust boundaries."],
            "reliability": ["Do not weaken recovery or availability requirements."],
            "performance": ["Validate representative peaks before implementation."],
        },
        "verification": {
            "method": "independent validation required",
            "result": "needs_validation",
            "notes": "No cost-changing action was performed.",
        },
        "implementation": {
            "steps": ["Prepare a reviewed IaC change after prerequisites are satisfied."],
            "validation": ["Compare performance, reachability, and recovery controls before cutover."],
            "rollback": ["Retain the prior configuration until owner acceptance and restore validation."],
        },
        "discovered_at": observed_at,
    }


def _storage_box_monthly(asset: Asset) -> float:
    kind = asset.properties.get("storage_box_type", {})
    location = asset.properties.get("location", {})
    if not isinstance(kind, dict) or not isinstance(location, dict):
        return 0.0
    return _price(kind.get("prices"), str(location.get("name", ""))) or 0.0


def _load_balancer_monthly(asset: Asset) -> float:
    kind = asset.properties.get("load_balancer_type", {})
    location = asset.properties.get("location", {})
    if not isinstance(kind, dict) or not isinstance(location, dict):
        return 0.0
    return _price(kind.get("prices"), str(location.get("name", ""))) or 0.0


def render_cost_markdown(report: dict[str, Any]) -> str:
    current = report["current_catalog_estimate"]
    potential = report["identified_potential_savings"]
    lines = [
        "# Hetzner Cost and Architecture Audit",
        "",
        f"- Current catalog estimate: **{report['currency']} {current['monthly_net']:.2f}/month** ({report['currency']} {current['annual_net']:.2f}/year)",
        f"- Potential savings identified: **{report['currency']} {potential['monthly_net']:.2f}/month** ({report['currency']} {potential['annual_net']:.2f}/year)",
        f"- Confirmed savings: **{report['currency']} {potential['confirmed_monthly_net']:.2f}/month**",
        "- All proposed savings require validation; no infrastructure changes were made.",
        "",
        "## Recommendations",
        "",
    ]
    if not report["recommendations"]:
        lines.append("No evidence-backed saving candidate was found with the available data.")
    for item in sorted(
        report["recommendations"],
        key=lambda value: value["estimated_savings"]["monthly"],
        reverse=True,
    ):
        saving = item["estimated_savings"]
        lines.extend(
            [
                f"### {item['rule_id']} · {item['title']}",
                "",
                f"- Asset: `{item['assets'][0]}`",
                f"- Status: `{item['status']}` · Risk: `{item['risk']}` · Confidence: `{item['confidence']:.2f}`",
                f"- Estimated saving: **EUR {saving['monthly']:.2f}/month · EUR {saving['annual']:.2f}/year**",
                f"- Current: `{item['current_state'].get('server_type')}` · EUR {item['current_state'].get('monthly_net', 0):.2f}/month total",
                f"- Candidate: `{item['candidate_state'].get('server_type', item['candidate_state'].get('action'))}`",
                "- Required validation: " + "; ".join(item["prerequisites"]),
                "",
            ]
        )
    lines.extend(["## Data gaps", "", *[f"- {gap}" for gap in report["data_gaps"]]])
    return "\n".join(lines)
