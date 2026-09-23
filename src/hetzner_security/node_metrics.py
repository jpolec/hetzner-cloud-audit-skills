"""Guest telemetry (RAM, root filesystem) from node exporter via Prometheus.

The Hetzner API reports CPU, disk I/O, and network, but not guest RAM or filesystem occupancy,
so rightsizing cannot be more than a hypothesis without them. This module reads a small JSON
file (see ``NODE_METRICS_EXAMPLE``) or builds it with read-only instant queries against a
Prometheus you point it at. Hosts are matched to servers by node exporter ``nodename``.
"""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from copy import deepcopy
from pathlib import Path
from typing import Any

from .models import Snapshot

MAX_METRICS_BYTES = 16 * 1024 * 1024
ROOT_FS = 'mountpoint="/",fstype!~"tmpfs|overlay|squashfs"'
QUERIES = {
    "ram_p95_percent": "quantile_over_time(0.95, (100 * (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes))[{days}d:5m])",
    "ram_p95_7d_percent": "quantile_over_time(0.95, (100 * (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes))[7d:5m])",
    "ram_max_percent": "max_over_time((100 * (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes))[{days}d:5m])",
    "disk_used_max_percent": f"max_over_time((100 * (1 - node_filesystem_avail_bytes{{{ROOT_FS}}} / node_filesystem_size_bytes{{{ROOT_FS}}}))[{{days}}d:1h])",
    "disk_size_gb": f"node_filesystem_size_bytes{{{ROOT_FS}}} / 1e9",
    "coverage_days": "(time() - min_over_time(timestamp(node_memory_MemTotal_bytes)[{days}d:1h])) / 86400",
}
NODE_METRICS_EXAMPLE = {
    "window_days": 30,
    "source": "prometheus",
    "hosts": {"app-1": {"ram_p95_percent": 38.5, "ram_p95_7d_percent": 40.1, "ram_max_percent": 71.0,
                        "disk_used_max_percent": 52.0, "disk_size_gb": 76.0, "coverage_days": 29.6}},
}


def load_node_metrics(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_METRICS_BYTES:
        raise ValueError(f"node metrics file {path} exceeds {MAX_METRICS_BYTES} bytes")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("hosts"), dict):
        raise ValueError(f"{path} must be a JSON object with a 'hosts' mapping (see `hetzner-audit metrics --example`)")
    return raw


def apply_node_metrics(snapshot: Snapshot, metrics: dict[str, Any]) -> Snapshot:
    result = deepcopy(snapshot)
    window = metrics.get("window_days")
    matched: list[str] = []
    for asset in result.assets:
        if asset.type != "server":
            continue
        values = metrics["hosts"].get(asset.name) or metrics["hosts"].get(asset.id)
        if not isinstance(values, dict):
            continue
        asset.properties["guest_metrics"] = {**values, "window_days": window, "source": metrics.get("source", "file")}
        matched.append(asset.name)
    result.metadata["node_metrics"] = {
        "window_days": window,
        "hosts": len(metrics["hosts"]),
        "matched": sorted(matched),
        "unmatched": sorted(set(metrics["hosts"]) - set(matched)),
    }
    return result


def collect_prometheus(url: str, days: int = 30, *, urlopen: Any = urllib.request.urlopen) -> dict[str, Any]:
    """Run the fixed read-only instant queries and group results by node exporter nodename."""
    base = url.rstrip("/")
    if not base.startswith(("https://", "http://")):
        raise ValueError("--prometheus must be an http(s) URL")
    headers = {"Accept": "application/json"}
    token = os.environ.get("PROMETHEUS_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    def query(expression: str) -> list[dict[str, Any]]:
        request = urllib.request.Request(  # noqa: S310 -- owner-supplied Prometheus URL, GET only
            f"{base}/api/v1/query?{urllib.parse.urlencode({'query': expression})}", headers=headers, method="GET"
        )
        with urlopen(request, timeout=60) as response:
            payload = json.loads(response.read())
        if payload.get("status") != "success":
            raise ValueError(f"Prometheus query failed: {payload.get('error', 'unknown error')}")
        return list(payload.get("data", {}).get("result", []))

    names = {
        item["metric"].get("instance"): item["metric"].get("nodename")
        for item in query("node_uname_info")
        if item.get("metric", {}).get("nodename")
    }
    hosts: dict[str, dict[str, float]] = {}
    for key, template in QUERIES.items():
        for item in query(template.replace("{days}", str(days))):
            instance = item.get("metric", {}).get("instance")
            name = names.get(instance) or str(instance).rsplit(":", 1)[0]
            try:
                value = float(item["value"][1])
            except (KeyError, IndexError, TypeError, ValueError):
                continue
            if value == value:  # skip NaN
                hosts.setdefault(name, {})[key] = round(value, 2)
    return {"window_days": days, "source": "prometheus", "hosts": hosts}
