"""Terraform <-> runtime drift from ``terraform show -json`` (state or saved plan).

The loader reads JSON the owner produced; it never runs Terraform. Resources are matched to
snapshot assets by provider ID. Firewall rules become network-access expectations, which the
existing HETZ-IAC-001 rule compares with the observed sources.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from .models import Snapshot

MAX_TERRAFORM_BYTES = 128 * 1024 * 1024
# Terraform resource type -> snapshot asset type.
MANAGED_TYPES = {
    "hcloud_server": "server",
    "hcloud_firewall": "firewall",
    "hcloud_network": "network",
    "hcloud_volume": "volume",
    "hcloud_load_balancer": "load_balancer",
    "hcloud_primary_ip": "primary_ip",
    "hcloud_floating_ip": "floating_ip",
    "hcloud_certificate": "certificate",
    "hcloud_managed_certificate": "certificate",
    "hcloud_uploaded_certificate": "certificate",
    "hcloud_placement_group": "placement_group",
    "hcloud_ssh_key": "ssh_key",
}
SECURITY_CHANGE_TYPES = {"hcloud_firewall", "hcloud_firewall_attachment", "hcloud_server", "hcloud_network", "hcloud_load_balancer"}


def _walk(module: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(module, dict):
        return []
    resources = [item for item in module.get("resources", []) or [] if isinstance(item, dict) and item.get("mode", "managed") == "managed"]
    if any(not isinstance(item, dict) for item in module.get("resources", []) or []):
        raise ValueError("unexpected Terraform JSON: resources must be objects")
    for child in module.get("child_modules", []) or []:
        resources.extend(_walk(child))
    return resources


def load_terraform(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    if size > MAX_TERRAFORM_BYTES:
        raise ValueError(f"terraform JSON {path} is {size} bytes; the limit is {MAX_TERRAFORM_BYTES}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or "format_version" not in raw:
        raise ValueError(f"{path} is not `terraform show -json` output")
    is_plan = "resource_changes" in raw
    # A plan declares what the configuration wants (planned_values); prior_state is refreshed runtime.
    state = raw.get("planned_values") if is_plan else raw.get("values")
    if state is not None and not isinstance(state, dict):
        raise ValueError(f"{path}: unexpected Terraform JSON shape")
    resources: list[dict[str, Any]] = [
        {"address": item.get("address"), "type": item.get("type"),
         "values": item.get("values") if isinstance(item.get("values"), dict) else {}}
        for item in _walk((state or {}).get("root_module"))
        if str(item.get("type", "")).startswith("hcloud_")
    ]
    changes = [
        {"address": item.get("address"), "type": item.get("type"), "actions": (item.get("change") or {}).get("actions", [])}
        for item in raw.get("resource_changes", []) or []
        if isinstance(item, dict) and str(item.get("type", "")).startswith("hcloud_")
        and (item.get("change") or {}).get("actions") not in (["no-op"], ["read"], None)
    ]
    return {"kind": "plan" if is_plan else "state", "resources": resources, "changes": changes, "source": path.name}


def _port_key(protocol: object, port: object) -> tuple[str, str]:
    protocol = str(protocol or "tcp")
    if protocol not in {"tcp", "udp"}:
        return protocol, "-"
    if port in (None, "", "any"):
        return protocol, "any"
    return protocol, str(port)


def _runtime_port(rule: dict[str, Any]) -> tuple[str, str]:
    first, last = rule.get("port_from"), rule.get("port_to")
    if first is None:
        return _port_key(rule.get("protocol"), None)
    return _port_key(rule.get("protocol"), first if first == last or last is None else f"{first}-{last}")


def _asset_id(resource: dict[str, Any]) -> str | None:
    kind = MANAGED_TYPES.get(str(resource.get("type")))
    value = resource["values"].get("id")
    return f"hcloud:{kind}:{value}" if kind and value not in (None, "") else None


def _attribute_drift(declared: dict[str, Any], observed: dict[str, Any], asset_type: str) -> dict[str, tuple[Any, Any]]:
    """Security- and cost-relevant attributes where Terraform and the API disagree."""
    diff: dict[str, tuple[Any, Any]] = {}

    def check(name: str, want: Any, have: Any) -> None:
        if want is not None and want != have:
            diff[name] = (want, have)

    if asset_type == "server":
        server_type = observed.get("server_type")
        check("server_type", declared.get("server_type"), server_type.get("name") if isinstance(server_type, dict) else server_type)
        protection = observed.get("protection") or {}
        check("delete_protection", declared.get("delete_protection"), protection.get("delete", observed.get("delete_protection")))
        check("rebuild_protection", declared.get("rebuild_protection"), protection.get("rebuild"))
        check("backups", declared.get("backups"), observed.get("backup_enabled"))
        if declared.get("firewall_ids") is not None:
            check("firewall_ids", sorted(int(item) for item in declared["firewall_ids"]),
                  sorted(int(item) for item in observed.get("firewall_ids") or []))
    if asset_type in {"volume", "primary_ip", "floating_ip", "network", "load_balancer", "firewall"}:
        protection = observed.get("protection") or {}
        check("delete_protection", declared.get("delete_protection"), protection.get("delete"))
    if isinstance(declared.get("labels"), dict) and declared["labels"]:
        observed_labels = observed.get("labels") or {}
        missing = {key: value for key, value in declared["labels"].items() if observed_labels.get(key) != value}
        if missing:
            diff["labels"] = (missing, {key: observed_labels.get(key) for key in missing})
    return diff


def apply_terraform(snapshot: Snapshot, path: Path) -> Snapshot:
    terraform = load_terraform(path)
    result = deepcopy(snapshot)
    assets = result.asset_map()
    managed: dict[str, str] = {}
    missing: list[dict[str, Any]] = []
    drift: list[dict[str, Any]] = []
    for resource in terraform["resources"]:
        asset_id = _asset_id(resource)
        if asset_id is None:
            continue
        managed[asset_id] = str(resource["address"])
        asset = assets.get(asset_id)
        if asset is None:
            missing.append({"address": resource["address"], "asset_id": asset_id, "type": resource["type"]})
            continue
        observed_state = {**asset.properties, "labels": asset.labels or asset.properties.get("labels") or {}}
        attributes = _attribute_drift(resource["values"], observed_state, asset.type)
        if attributes:
            drift.append({"address": resource["address"], "asset_id": asset_id, "attributes": {k: list(v) for k, v in attributes.items()}})
        if resource["type"] == "hcloud_firewall":
            declared: dict[tuple[str, str], set[str]] = {}
            for rule in resource["values"].get("rule") or []:
                if rule.get("direction", "in") != "in":
                    continue
                declared.setdefault(_port_key(rule.get("protocol"), rule.get("port")), set()).update(rule.get("source_ips") or [])
            observed: dict[tuple[str, str], set[str]] = {}
            for rule in asset.properties.get("inbound") or []:
                observed.setdefault(_runtime_port(rule), set()).update(rule.get("sources") or [])
            for key in sorted(set(declared) | set(observed)):
                protocol, port = key
                result.expectations.append(
                    {
                        "kind": "network_access",
                        "target": asset_id,
                        "port": int(port) if port.isdigit() else 0,
                        "port_spec": f"{protocol}/{port}",
                        "allowed_sources": sorted(declared.get(key, set())),
                        "observed_sources": sorted(observed.get(key, set())),
                        "declared": {"address": resource["address"], "protocol": protocol, "port": port},
                        "path": terraform["source"],
                    }
                )
    managed_types = {MANAGED_TYPES[str(resource["type"])] for resource in terraform["resources"] if resource["type"] in MANAGED_TYPES}
    unmanaged = [
        {"asset_id": asset.id, "type": asset.type, "name": asset.name}
        for asset in result.assets
        if asset.type in managed_types and asset.source == "hcloud_api" and asset.id not in managed
    ]
    result.metadata["terraform"] = {
        "source": terraform["source"],
        "kind": terraform["kind"],
        "resources": len(terraform["resources"]),
        "managed": managed,
        "missing": missing,
        "unmanaged": unmanaged,
        "attribute_drift": drift,
        "pending_changes": terraform["changes"],
    }
    return result
