"""Minimal read-only Hetzner Cloud API collector.

The module intentionally implements only HTTP GET and exposes no generic request method.
"""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from typing import Any

from ..models import Asset, Edge, Evidence, Snapshot

API_BASE = "https://api.hetzner.cloud/v1"
RESOURCE_ENDPOINTS = {
    "server": "servers",
    "server_type": "server_types",
    "image": "images",
    "location": "locations",
    "datacenter": "datacenters",
    "network": "networks",
    "firewall": "firewalls",
    "primary_ip": "primary_ips",
    "floating_ip": "floating_ips",
    "load_balancer": "load_balancers",
    "volume": "volumes",
    "ssh_key": "ssh_keys",
    "placement_group": "placement_groups",
    "certificate": "certificates",
    "zone": "zones",
}


class HCloudCollectionError(RuntimeError):
    pass


class ReadOnlyHCloudCollector:
    def __init__(self, token: str | None = None, *, base_url: str = API_BASE) -> None:
        self._token = token or os.environ.get("HCLOUD_TOKEN")
        self.base_url = base_url.rstrip("/")
        if not self._token:
            raise HCloudCollectionError("HCLOUD_TOKEN is required for live collection")

    def _get_page(self, endpoint: str, page: int) -> dict[str, Any]:
        query = urllib.parse.urlencode({"page": page, "per_page": 50})
        request = urllib.request.Request(  # noqa: S310 -- fixed HTTPS API base by default
            f"{self.base_url}/{endpoint}?{query}",
            headers={
                "Authorization": f"Bearer {self._token}",
                "User-Agent": "hetzner-cloud-audit-skills/0.2.0",
                "Accept": "application/json",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
                payload: Any = json.loads(response.read())
                if not isinstance(payload, dict):
                    raise HCloudCollectionError(f"unexpected response shape for {endpoint}")
                return {str(key): value for key, value in payload.items()}
        except Exception as exc:
            raise HCloudCollectionError(f"read-only GET failed for {endpoint}: {exc}") from exc

    def _list(self, endpoint: str, response_key: str | None = None) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        page = 1
        key = response_key or endpoint
        while True:
            payload = self._get_page(endpoint, page)
            output.extend(payload.get(key, []))
            pagination = payload.get("meta", {}).get("pagination", {})
            if not pagination.get("next_page"):
                break
            page = int(pagination["next_page"])
        return output

    def collect(self) -> Snapshot:
        assets: list[Asset] = []
        edges: list[Edge] = []
        raw_by_kind: dict[str, list[dict[str, Any]]] = {}
        for kind, endpoint in RESOURCE_ENDPOINTS.items():
            rows = self._list(endpoint)
            raw_by_kind[kind] = rows
            for row in rows:
                rid = str(row.get("id", row.get("name", "unknown")))
                asset_kind = str(row.get("type")) if kind == "image" and row.get("type") in {"snapshot", "backup"} else kind
                assets.append(
                    Asset(
                        id=f"hcloud:{asset_kind}:{rid}",
                        type=asset_kind,
                        name=str(row.get("name", rid)),
                        properties=_sanitize_resource(row),
                        labels={str(k): str(v) for k, v in row.get("labels", {}).items()},
                        source="hcloud_api",
                    )
                )
        for zone in raw_by_kind.get("zone", []):
            zone_id = str(zone.get("id", zone.get("name", "unknown")))
            for rrset in self._list(f"zones/{zone_id}/rrsets", "rrsets"):
                rr_name = str(rrset.get("name", "unknown"))
                rr_type = str(rrset.get("type", "unknown"))
                assets.append(
                    Asset(
                        id=f"hcloud:rrset:{zone_id}:{rr_name}:{rr_type}",
                        type="dns_rrset",
                        name=f"{rr_name} {rr_type}",
                        properties=_sanitize_resource(rrset),
                        source="hcloud_api",
                    )
                )
                edges.append(
                    Edge(
                        source=f"hcloud:zone:{zone_id}",
                        target=f"hcloud:rrset:{zone_id}:{rr_name}:{rr_type}",
                        relation="contains",
                    )
                )
        edges.extend(_derive_edges(raw_by_kind))
        return Snapshot(
            assets=assets,
            edges=edges,
            metadata={
                "collector": "hcloud_api",
                "read_only": True,
                "collected_at": datetime.now(UTC).isoformat(),
            },
        )


def _sanitize_resource(value: Any, key: str = "") -> Any:
    """Redact key-like fields defensively before evidence can reach a report."""
    secret_names = {"token", "password", "private_key", "secret", "user_data"}
    if key.lower() in secret_names:
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _sanitize_resource(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_resource(item, key) for item in value]
    return value


def _derive_edges(raw: dict[str, list[dict[str, Any]]]) -> list[Edge]:
    edges: list[Edge] = []
    for server in raw.get("server", []):
        sid = f"hcloud:server:{server['id']}"
        public_net = server.get("public_net", {})
        if public_net.get("ipv4", {}).get("ip") or public_net.get("ipv6", {}).get("ip"):
            edges.append(
                Edge(
                    source="internet",
                    target=sid,
                    relation="public_interface",
                    evidence=(Evidence("hcloud_api", "public_network", sid, public_net),),
                )
            )
        for private_net in server.get("private_net", []):
            network_id = private_net.get("network")
            if network_id is not None:
                edges.append(
                    Edge(
                        source=sid,
                        target=f"hcloud:network:{network_id}",
                        relation="attached_to",
                        evidence=(
                            Evidence("hcloud_api", "private_network", sid, private_net),
                        ),
                    )
                )
                edges.append(
                    Edge(
                        source=f"hcloud:network:{network_id}",
                        target=sid,
                        relation="contains",
                    )
                )
    for firewall in raw.get("firewall", []):
        fid = f"hcloud:firewall:{firewall['id']}"
        for applied in firewall.get("applied_to", []):
            server = applied.get("server", {}).get("id")
            if server is not None:
                edges.append(Edge(fid, f"hcloud:server:{server}", "protects"))
    return edges
