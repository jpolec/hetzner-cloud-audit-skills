"""Deterministic snapshot comparison with collection-coverage awareness."""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

from .flows import egress_flowspace, flowspace_growth, snapshot_flowspace
from .models import Edge, Snapshot
from .text import md


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _edge_key(edge: Edge) -> tuple[str, str, str, str | None, int | None]:
    return edge.source, edge.target, edge.relation, edge.protocol, edge.port


def diff_snapshots(before: Snapshot, after: Snapshot, regression_policy: str = "broad") -> dict[str, Any]:
    """Structural drift (facts, edges, assets) plus security drift (exact allowed-flow difference).

    ``regression_policy``: ``broad`` fails on new world or wide exposure; ``strict`` fails on any
    increase of the allowed flow space, including a wider allow-list or a different trusted source.
    """
    before_assets = before.asset_map()
    after_assets = after.asset_map()
    before_facts = {fact.id: fact for fact in before.facts}
    after_facts = {fact.id: fact for fact in after.facts}
    before_edges = {_edge_key(edge): edge for edge in before.edges}
    after_edges = {_edge_key(edge): edge for edge in after.edges}

    changed_facts = []
    for fact_id in sorted(before_facts.keys() & after_facts.keys()):
        old = before_facts[fact_id]
        new = after_facts[fact_id]
        if _canonical(old.value) == _canonical(new.value):
            continue
        changed_facts.append(
            {
                "fact_id": fact_id,
                "asset_id": new.asset_id,
                "kind": new.kind,
                "before": old.value,
                "after": new.value,
                "first_observed": new.observed_at,
            }
        )

    new_edges = [after_edges[key] for key in sorted(after_edges.keys() - before_edges.keys())]
    removed_edge_candidates = [before_edges[key] for key in sorted(before_edges.keys() - after_edges.keys())]
    # Semantic exposure diff: flows allowed now minus flows allowed before (see flows.py).
    if regression_policy not in {"broad", "strict"}:
        raise ValueError("regression policy must be broad or strict")
    before_space, after_space = snapshot_flowspace(before), snapshot_flowspace(after)
    growth = flowspace_growth(before_space, after_space)
    # The reverse difference: flows allowed before and not now (a closed rule or a removed public IP).
    closed = flowspace_growth(after_space, before_space)
    new_egress = flowspace_growth(
        {asset.id: space for asset in before.assets if (space := egress_flowspace(asset))},
        {asset.id: space for asset in after.assets if (space := egress_flowspace(asset))},
    )
    for item in new_egress:
        asset = after_assets.get(item["asset"])
        item["name"] = asset.name if asset else item["asset"]
    for item in closed:
        asset = before_assets.get(item["asset"])
        item["name"] = asset.name if asset else item["asset"]
    for item in growth:
        asset = after_assets.get(item["asset"])
        item["name"] = asset.name if asset else item["asset"]
    new_exposures = [item for item in growth if item["source_class"] in {"world", "wide"}]
    new_allowlisted = [item for item in growth if item["source_class"] == "allowlist"]
    coverage_regressions = _coverage_regressions(before, after)
    regressed_sources = {item["source"] for item in coverage_regressions}
    removed_candidates = sorted(before_assets.keys() - after_assets.keys())
    uncertain_removed_assets = [
        asset_id
        for asset_id in removed_candidates
        if _coverage_key(before_assets[asset_id].type) in regressed_sources
    ]
    removed_assets = [asset_id for asset_id in removed_candidates if asset_id not in uncertain_removed_assets]
    uncertain_removed_edges = [
        edge
        for edge in removed_edge_candidates
        if _edge_has_regressed_source(edge, before_assets, regressed_sources)
    ]
    removed_edges = [edge for edge in removed_edge_candidates if edge not in uncertain_removed_edges]

    return {
        "schema_version": "1.0.0",
        "before": _snapshot_identity(before),
        "after": _snapshot_identity(after),
        "added_assets": sorted(after_assets.keys() - before_assets.keys()),
        "removed_assets": removed_assets,
        "uncertain_removed_assets": uncertain_removed_assets,
        "changed_facts": changed_facts,
        "new_edges": [edge.to_dict() for edge in new_edges],
        "removed_edges": [edge.to_dict() for edge in removed_edges],
        "uncertain_removed_edges": [edge.to_dict() for edge in uncertain_removed_edges],
        "new_exposures": new_exposures,
        "new_allowlisted_flows": new_allowlisted,
        "closed_exposures": closed,
        "new_egress": new_egress,
        "coverage_regressions": coverage_regressions,
        "regression_policy": regression_policy,
        "security_regression": bool(new_exposures) if regression_policy == "broad" else bool(growth or new_egress),
        "cost": _cost_delta(before, after),
    }


def _reprice(snapshot: Snapshot, catalog: Snapshot) -> Snapshot:
    """``snapshot``'s resources priced with ``catalog``'s price list (server, LB, and Storage Box types, pricing)."""
    priced = deepcopy(snapshot)
    types: dict[tuple[str, str], Any] = {}
    for asset in catalog.assets:
        if asset.type in {"server_type", "load_balancer_type", "storage_box_type"}:
            types[(asset.type, asset.name)] = asset.properties
        if asset.type == "server" and isinstance(asset.properties.get("server_type"), dict):
            types.setdefault(("server_type", str(asset.properties["server_type"].get("name"))), asset.properties["server_type"])
    embedded = {"server": "server_type", "load_balancer": "load_balancer_type", "storage_box": "storage_box_type"}
    catalog_pricing = next((asset for asset in catalog.assets if asset.type == "pricing"), None)
    for asset in priced.assets:
        key = embedded.get(asset.type)
        current = asset.properties.get(key) if key else None
        if key and isinstance(current, dict) and (key, str(current.get("name"))) in types:
            asset.properties[key] = {**current, "prices": types[(key, str(current.get("name")))].get("prices", current.get("prices"))}
        if asset.type == "pricing" and catalog_pricing is not None:
            asset.properties = deepcopy(catalog_pricing.properties)
    return priced


def _cost_delta(before: Snapshot, after: Snapshot) -> dict[str, Any] | None:
    """Measured catalog delta, split into the effect of resource changes and of provider price changes.

    attributable = cost(before resources, before prices) - cost(after resources, before prices)
    price drift  = cost(after resources, after prices)   - cost(after resources, before prices)
    Neither is invoice-verified: catalog prices, net of VAT, credits, and discounts.
    """
    if not all(any(asset.type == "pricing" for asset in item.assets) for item in (before, after)):
        return None
    from .cost import analyze_cost

    gaps = [
        f"{label}:{name}"
        for label, item in (("before", before), ("after", after))
        for name, state in (item.metadata.get("coverage") or {}).items()
        if isinstance(state, dict) and state.get("status") in {"failed", "partial"}
        and name in {"server", "volume", "primary_ip", "floating_ip", "load_balancer", "storage_box", "image", "pricing"}
    ]
    if gaps:
        return {"attributable_monthly_savings": None, "not_comparable": f"collection gaps: {', '.join(gaps)}"}

    def total(snapshot: Snapshot) -> float:
        return float(analyze_cost(snapshot)["current_catalog_estimate"]["monthly_net"])

    old, new = total(before), total(after)
    after_at_old_prices = total(_reprice(after, before))
    return {
        "before_monthly_net": old,
        "after_monthly_net": new,
        "catalog_delta_monthly": round(old - new, 2),
        "attributable_monthly_savings": round(old - after_at_old_prices, 2),
        "price_drift_monthly": round(new - after_at_old_prices, 2),
        "basis": "catalog prices, net; not reconciled with invoices",
    }


def _snapshot_identity(snapshot: Snapshot) -> dict[str, Any]:
    return {
        "run_id": snapshot.metadata.get("run_id"),
        "collected_at": snapshot.metadata.get("collected_at"),
        "collector_version": snapshot.metadata.get("collector_version"),
    }


def _coverage_regressions(before: Snapshot, after: Snapshot) -> list[dict[str, Any]]:
    old = before.metadata.get("coverage", {})
    new = after.metadata.get("coverage", {})
    if not isinstance(old, dict) or not isinstance(new, dict):
        return []
    regressions = []
    for source, previous in old.items():
        current = new.get(source, {})
        if not isinstance(previous, dict) or not isinstance(current, dict):
            continue
        if previous.get("status") == "collected" and current.get("status") != "collected":
            regressions.append(
                {"source": source, "before": previous.get("status"), "after": current.get("status", "missing")}
            )
    return regressions


def _coverage_key(asset_type: str) -> str:
    return {"backup": "image", "snapshot": "image", "dns_rrset": "zone"}.get(
        asset_type, asset_type
    )


def _edge_has_regressed_source(
    edge: Edge, assets: dict[str, Any], regressed_sources: set[str]
) -> bool:
    for asset_id in (edge.source, edge.target):
        asset = assets.get(asset_id)
        if asset is not None and _coverage_key(asset.type) in regressed_sources:
            return True
    return False


def _flow_line(item: dict[str, Any]) -> str:
    sources = item.get("sources") or []
    shown = ", ".join(sources[:4]) + (" …" if len(sources) > 4 else "")
    count = item.get("source_addresses")
    return (
        f"- `{md(item.get('name', item['asset']))}` · {item['family']} {item['protocol'].upper()} {item['ports']} "
        f"from {item['source_class']} ({md(shown) or 'unknown'}"
        + (f"; {count:,} addresses" if isinstance(count, int) else "") + ")"
    )


def render_diff_markdown(diff: dict[str, Any]) -> str:
    lines = [
        "# Hetzner Infrastructure Diff",
        "",
        f"- Added assets: {len(diff['added_assets'])}",
        f"- Removed assets: {len(diff['removed_assets'])}",
        f"- Uncertain removals due to collection gaps: {len(diff['uncertain_removed_assets'])}",
        f"- Changed facts: {len(diff['changed_facts'])}",
        f"- New exposures: {len(diff['new_exposures'])}",
        f"- Coverage regressions: {len(diff['coverage_regressions'])}",
        f"- Security policy regression ({diff.get('regression_policy', 'broad')}): {'yes' if diff['security_regression'] else 'no'}",
        "",
    ]
    cost = diff.get("cost")
    if cost and cost.get("attributable_monthly_savings") is None:
        lines[-1:-1] = [f"- Catalog cost: not compared ({cost.get('not_comparable')})"]
    elif cost:
        lines[-1:-1] = [
            f"- Catalog cost: EUR {cost['before_monthly_net']:.2f} → EUR {cost['after_monthly_net']:.2f}/month · "
            f"saving from your changes EUR {cost['attributable_monthly_savings']:.2f}/month (priced at the earlier catalog) · "
            f"provider price changes EUR {cost['price_drift_monthly']:+.2f}/month · catalog prices, not invoices"
        ]
    if diff["new_exposures"]:
        lines.extend(["## New exposure (flows allowed now that were not allowed before)", ""])
        lines.extend(_flow_line(item) for item in diff["new_exposures"])
        lines.append("")
    if diff.get("closed_exposures"):
        lines.extend(["## Closed exposure (flows allowed before that are not allowed now)", ""])
        lines.extend(_flow_line(item) for item in diff["closed_exposures"])
        lines.append("")
    if diff.get("new_egress"):
        lines.extend(["## New Internet egress (destinations the servers may now reach)", ""])
        lines.extend(_flow_line(item) for item in diff["new_egress"])
        lines.append("")
    if diff.get("new_allowlisted_flows"):
        lines.extend(["## Newly allowed sources (allow-lists and edge proxies)", ""])
        lines.extend(_flow_line(item) for item in diff["new_allowlisted_flows"])
        lines.append("")
    if diff["coverage_regressions"]:
        lines.extend(["## Coverage regressions", ""])
        for item in diff["coverage_regressions"]:
            lines.append(f"- `{item['source']}`: {item['before']} → {item['after']}")
        lines.append("")
    if diff["changed_facts"]:
        lines.extend(["## Changed facts", ""])
        for item in diff["changed_facts"]:
            lines.append(f"- `{item['asset_id']}` · `{item['kind']}`")
    return "\n".join(lines)
