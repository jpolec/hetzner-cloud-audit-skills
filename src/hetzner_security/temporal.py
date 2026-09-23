"""Deterministic snapshot comparison with collection-coverage awareness."""

from __future__ import annotations

import json
from typing import Any

from .flows import exposure_growth, snapshot_exposure
from .models import Edge, Snapshot
from .text import md


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _edge_key(edge: Edge) -> tuple[str, str, str, str | None, int | None]:
    return edge.source, edge.target, edge.relation, edge.protocol, edge.port


def diff_snapshots(before: Snapshot, after: Snapshot) -> dict[str, Any]:
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
    growth = exposure_growth(snapshot_exposure(before), snapshot_exposure(after))
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
        "coverage_regressions": coverage_regressions,
        "security_regression": bool(new_exposures),
        "cost": _cost_delta(before, after),
    }


def _cost_delta(before: Snapshot, after: Snapshot) -> dict[str, Any] | None:
    """Verified savings: the catalog cost measured before and after, when both snapshots carry pricing."""
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
        return {"verified_monthly_savings": None, "unverifiable": f"collection gaps: {', '.join(gaps)}"}
    old = analyze_cost(before)["current_catalog_estimate"]["monthly_net"]
    new = analyze_cost(after)["current_catalog_estimate"]["monthly_net"]
    return {"before_monthly_net": old, "after_monthly_net": new, "verified_monthly_savings": round(old - new, 2)}


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
        f"- Security policy regression: {'yes' if diff['security_regression'] else 'no'}",
        "",
    ]
    cost = diff.get("cost")
    if cost and cost.get("verified_monthly_savings") is None:
        lines[-1:-1] = [f"- Catalog cost: not compared ({cost.get('unverifiable')})"]
    elif cost:
        lines[-1:-1] = [
            f"- Catalog cost: EUR {cost['before_monthly_net']:.2f} → EUR {cost['after_monthly_net']:.2f}/month "
            f"(verified saving EUR {cost['verified_monthly_savings']:.2f}/month)"
        ]
    if diff["new_exposures"]:
        lines.extend(["## New exposure (flows allowed now that were not allowed before)", ""])
        for item in diff["new_exposures"]:
            lines.append(
                f"- `{md(item.get('name', item['asset']))}` · {item['family']} {item['protocol'].upper()} "
                f"{item['ports']} from {item['source_class']} sources"
            )
        lines.append("")
    if diff.get("new_allowlisted_flows"):
        lines.extend(["## New allow-listed flows (specific public sources)", ""])
        for item in diff["new_allowlisted_flows"]:
            lines.append(f"- `{md(item.get('name', item['asset']))}` · {item['family']} {item['protocol'].upper()} {item['ports']}")
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
