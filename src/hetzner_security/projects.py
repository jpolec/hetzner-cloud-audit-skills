"""Several Hetzner Cloud projects in one report.

Each project needs its own read-only token, so each is snapshotted separately (``snapshot
--project NAME --token-env VAR``) and then merged. Hetzner resource IDs are unique across
projects, so asset IDs stay as they are; every asset records its project. Private networks
never span projects, so traffic between projects crosses the public Internet or a vSwitch:
that is the trust boundary the cross-project rules look at.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .collectors.fixture import load_snapshot
from .models import Asset, Snapshot

# Catalog assets are the same in every project; keep one copy.
SHARED_TYPES = {"server_type", "location", "datacenter", "load_balancer_type", "storage_box_type", "pricing"}


def tag_project(snapshot: Snapshot, name: str) -> Snapshot:
    if snapshot.metadata.get("projects"):
        raise ValueError("--project cannot re-tag a merged multi-project snapshot")
    snapshot.metadata["project"] = name
    for asset in snapshot.assets:
        if asset.type not in SHARED_TYPES:
            asset.properties["project"] = name
    return snapshot


def _shared(asset: Asset) -> bool:
    """Assets that legitimately appear in several project snapshots with the same ID."""
    if asset.type in SHARED_TYPES or asset.id.startswith(("robot:", "s3:", "k8s:")):
        return True  # catalog data, or account-level sources snapshotted alongside each project
    return asset.type == "image" and asset.properties.get("type") in {"system", "app"}


def _merge_metadata(merged: Snapshot, name: str, metadata: dict[str, Any]) -> None:
    """Carry optional evidence through the merge so the rules that read it keep working."""
    meta = merged.metadata
    for bundle in metadata.get("host_bundles") or []:
        meta.setdefault("host_bundles", []).append({**bundle, "project": name})
    terraform = metadata.get("terraform")
    if isinstance(terraform, dict):
        into = meta.setdefault("terraform", {"source": [], "kind": terraform["kind"], "resources": 0, "managed": {},
                                             "missing": [], "unmanaged": [], "attribute_drift": [], "pending_changes": []})
        into["source"] = [*into["source"], terraform["source"]] if isinstance(into["source"], list) else [into["source"], terraform["source"]]
        into["kind"] = into["kind"] if into["kind"] == terraform["kind"] else "mixed"
        into["resources"] += terraform["resources"]
        into["managed"].update(terraform["managed"])
        for key in ("missing", "unmanaged", "attribute_drift", "pending_changes"):
            into[key] = [*into[key], *terraform[key]]
    metrics = metadata.get("node_metrics")
    if isinstance(metrics, dict):
        into = meta.setdefault("node_metrics", {"window_days": metrics.get("window_days"), "hosts": 0, "matched": [], "unmatched": []})
        into["hosts"] += metrics.get("hosts", 0)
        into["matched"] = sorted({*into["matched"], *metrics.get("matched", [])})
        into["unmatched"] = sorted({*into["unmatched"], *metrics.get("unmatched", [])} - set(into["matched"]))
    # Account-level evidence: the first snapshot that carries it wins.
    for key in ("attestations", "kubernetes"):
        if metadata.get(key) and key not in meta:
            meta[key] = metadata[key]


def merge_snapshots(paths: list[Path]) -> Snapshot:
    merged = Snapshot(metadata={"projects": [], "coverage": {}})
    seen: set[str] = set()
    names: set[str] = set()
    edges: set[tuple[Any, ...]] = set()
    for path in paths:
        snapshot = load_snapshot(path)
        name = str(snapshot.metadata.get("project") or path.stem)
        if name in names:
            raise ValueError(f"two snapshots are named project {name!r}; snapshot each with a distinct --project")
        names.add(name)
        tag_project(snapshot, name)
        merged.metadata["projects"].append(
            {"name": name, "collected_at": snapshot.metadata.get("collected_at"), "assets": len(snapshot.assets), "source": path.name}
        )
        for kind, state in (snapshot.metadata.get("coverage") or {}).items():
            merged.metadata["coverage"][f"{name}:{kind}"] = state
        for asset in snapshot.assets:
            if asset.id in seen:
                if _shared(asset):
                    continue
                raise ValueError(f"asset {asset.id} appears in two projects; merge each project once")
            seen.add(asset.id)
            merged.assets.append(asset)
        for edge in snapshot.edges:
            edge_key = (edge.source, edge.target, edge.relation, edge.protocol, edge.port)
            if edge_key not in edges:
                edges.add(edge_key)
                merged.edges.append(edge)
        merged.facts.extend(snapshot.facts)
        merged.expectations.extend(snapshot.expectations)
        merged.signals.extend(snapshot.signals)
        _merge_metadata(merged, name, snapshot.metadata)
    times = [item["collected_at"] for item in merged.metadata["projects"] if item["collected_at"]]
    if times:
        merged.metadata["collected_at"] = max(times)
    merged.metadata["collector"] = "merged"
    merged.metadata["read_only"] = True
    return merged


def public_addresses(asset: Asset) -> list[str]:
    public = asset.properties.get("public_net") or {}
    values = [(public.get(family) or {}).get("ip") for family in ("ipv4", "ipv6")]
    if asset.type in {"primary_ip", "floating_ip"}:
        values.append(asset.properties.get("ip"))
    if asset.type == "robot_server":
        values.extend(asset.properties.get("ip") or [])
    return [str(value) for value in values if value]


def project_summary(snapshot: Snapshot) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, int]] = {}
    for asset in snapshot.assets:
        project = asset.properties.get("project")
        if project:
            row = rows.setdefault(str(project), {})
            row[asset.type] = row.get(asset.type, 0) + 1
    return [{"project": name, "assets": counts} for name, counts in sorted(rows.items())]
