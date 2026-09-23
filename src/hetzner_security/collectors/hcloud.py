"""Minimal read-only Hetzner Cloud API collector.

The module intentionally implements only HTTP GET and exposes no generic request method.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from typing import Any

from ..models import Asset, Edge, Evidence, Fact, Snapshot

API_BASE = "https://api.hetzner.cloud/v1"
HETZNER_API_BASE = "https://api.hetzner.com/v1"
COLLECTOR_VERSION = "0.3.1"
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
    "load_balancer_type": "load_balancer_types",
    "volume": "volumes",
    "ssh_key": "ssh_keys",
    "placement_group": "placement_groups",
    "certificate": "certificates",
    "zone": "zones",
}
HETZNER_RESOURCE_ENDPOINTS = {
    "storage_box": "storage_boxes",
    "storage_box_type": "storage_box_types",
}


class HCloudCollectionError(RuntimeError):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class ReadOnlyHCloudCollector:
    def __init__(
        self,
        token: str | None = None,
        *,
        base_url: str = API_BASE,
        include_metrics: bool = False,
        metrics_days: int = 30,
    ) -> None:
        self._token = token or os.environ.get("HCLOUD_TOKEN")
        self.base_url = base_url.rstrip("/")
        self.include_metrics = include_metrics
        self.metrics_days = metrics_days
        if not self._token:
            raise HCloudCollectionError("HCLOUD_TOKEN is required for live collection")

    def _get_page(self, endpoint: str, page: int) -> dict[str, Any]:
        base_url = self.base_url
        if endpoint.startswith("hetzner:"):
            endpoint = endpoint.removeprefix("hetzner:")
            base_url = HETZNER_API_BASE
        return self._get_json(endpoint, {"page": page, "per_page": 50}, base_url=base_url)

    def _get_json(
        self,
        endpoint: str,
        params: dict[str, object] | None = None,
        *,
        base_url: str | None = None,
    ) -> dict[str, Any]:
        query = urllib.parse.urlencode(params or {})
        suffix = f"?{query}" if query else ""
        request = urllib.request.Request(  # noqa: S310 -- fixed HTTPS API base by default
            f"{(base_url or self.base_url).rstrip('/')}/{endpoint}{suffix}",
            headers={
                "Authorization": f"Bearer {self._token}",
                "User-Agent": f"hetzner-cloud-audit-skills/{COLLECTOR_VERSION}",
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
        except urllib.error.HTTPError as exc:
            raise HCloudCollectionError(
                f"read-only GET failed for {endpoint}: HTTP {exc.code}", status=exc.code
            ) from exc
        except HCloudCollectionError:
            raise
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
        raw_by_kind: dict[str, list[dict[str, Any]]] = {}
        coverage: dict[str, dict[str, object]] = {}
        for kind, endpoint in RESOURCE_ENDPOINTS.items():
            try:
                rows = self._list(endpoint)
                coverage[kind] = {"status": "collected", "count": len(rows)}
            except HCloudCollectionError as exc:
                rows = []
                coverage[kind] = {"status": "failed", "error": str(exc)}
            raw_by_kind[kind] = rows
        for kind, endpoint in HETZNER_RESOURCE_ENDPOINTS.items():
            try:
                rows = self._list(f"hetzner:{endpoint}", endpoint)
                coverage[kind] = {"status": "collected", "count": len(rows)}
            except HCloudCollectionError as exc:
                rows = []
                coverage[kind] = {"status": "unavailable", "error": str(exc)}
            raw_by_kind[kind] = rows

        pricing: dict[str, Any] = {}
        try:
            value = self._get_page("pricing", 1).get("pricing", {})
            pricing = value if isinstance(value, dict) else {}
            coverage["pricing"] = {"status": "collected", "count": int(bool(pricing))}
        except HCloudCollectionError as exc:
            coverage["pricing"] = {"status": "failed", "error": str(exc)}

        if not any(raw_by_kind.get(kind) for kind in ("server", "network", "firewall")):
            failures = [kind for kind, state in coverage.items() if state["status"] == "failed"]
            if failures:
                raise HCloudCollectionError("no core assets collected; failed sources: " + ", ".join(failures))

        collected_at = datetime.now(UTC).isoformat()
        run_id = "run-" + hashlib.sha256(collected_at.encode()).hexdigest()[:16]
        if self.include_metrics:
            self._collect_server_metrics(raw_by_kind.get("server", []), coverage, collected_at)

        # Sanitize once so assets, labels, facts, and edge evidence all see redacted data.
        normalized: dict[str, list[dict[str, Any]]] = _sanitize_resource(_normalize_resources(raw_by_kind))
        for kind, rows in normalized.items():
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
        if pricing:
            assets.append(
                Asset(
                    id="hcloud:pricing:current",
                    type="pricing",
                    name="current Hetzner catalog pricing",
                    properties=_sanitize_resource(pricing),
                    source="hcloud_api",
                )
            )
        edges: list[Edge] = []
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
        edges.extend(_derive_edges(normalized))
        facts = _derive_facts(assets, collected_at, run_id)
        return Snapshot(
            assets=assets,
            edges=edges,
            facts=facts,
            metadata={
                "collector": "hcloud_api",
                "collector_version": COLLECTOR_VERSION,
                "run_id": run_id,
                "read_only": True,
                "collected_at": collected_at,
                "coverage": coverage,
            },
        )

    def _collect_server_metrics(
        self,
        servers: list[dict[str, Any]],
        coverage: dict[str, dict[str, object]],
        collected_at: str,
    ) -> None:
        end = datetime.fromisoformat(collected_at)
        start = end - timedelta(days=self.metrics_days)
        failures = 0
        for server in servers:
            server_id = server.get("id")
            if server_id is None:
                continue
            try:
                server["metrics"] = self._get_json(
                    f"servers/{server_id}/metrics",
                    {
                        "type": "cpu,disk,network",
                        "start": start.isoformat(),
                        "end": end.isoformat(),
                    },
                ).get("metrics", {})
            except HCloudCollectionError:
                server["metrics"] = {}
                failures += 1
        coverage["server_metrics"] = {
            "status": "collected" if failures == 0 else "partial",
            "count": len(servers) - failures,
            "failed": failures,
            "window_days": self.metrics_days,
        }


EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
SECRET_KEYS = {"token", "password", "private_key", "secret", "user_data"}
# Personal or account-identifying fields that no audit rule needs.
PERSONAL_KEYS = {"dns_ptr", "username"}


def _sanitize_resource(value: Any, key: str = "") -> Any:
    """Redact secrets and personal data before evidence can reach a snapshot or report."""
    lowered = key.lower()
    if lowered in SECRET_KEYS:
        return "[REDACTED]"
    if lowered in PERSONAL_KEYS:
        return "[REDACTED:personal]" if value not in (None, [], "") else value
    if lowered == "public_key" and isinstance(value, str):
        # Keep the key type for evidence; drop key material and the comment (often an email).
        return (value.split()[0] + " [key material and comment omitted]") if value.strip() else value
    if isinstance(value, dict):
        return {str(k): _sanitize_resource(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_resource(item, key) for item in value]
    if isinstance(value, str):
        return EMAIL_PATTERN.sub("[REDACTED:email]", value)
    return value


def _parse_port(value: object) -> tuple[int | None, int | None]:
    if value in (None, "any"):
        return None, None
    if isinstance(value, int):
        return value, value
    if isinstance(value, str) and "-" in value:
        start, end = value.split("-", 1)
        if start.isdigit() and end.isdigit():
            return int(start), int(end)
    if isinstance(value, str) and value.isdigit():
        return int(value), int(value)
    return None, None


def _normal_rule(rule: dict[str, Any]) -> dict[str, Any]:
    start, end = _parse_port(rule.get("port"))
    return {
        "direction": rule.get("direction"),
        "protocol": rule.get("protocol", "tcp"),
        "port": start if start == end else rule.get("port", "any"),
        "port_from": start,
        "port_to": end,
        "sources": list(rule.get("source_ips", [])),
        "destinations": list(rule.get("destination_ips", [])),
        "description": rule.get("description"),
    }


def _normalize_resources(
    raw: dict[str, list[dict[str, Any]]],
) -> dict[str, list[dict[str, Any]]]:
    normalized = {kind: [dict(row) for row in rows] for kind, rows in raw.items()}
    firewalls = {row.get("id"): row for row in raw.get("firewall", [])}
    for firewall in normalized.get("firewall", []):
        firewall["inbound"] = [
            _normal_rule(rule) for rule in firewall.get("rules", []) if rule.get("direction") == "in"
        ]
    for server in normalized.get("server", []):
        public_net = server.get("public_net", {})
        firewall_ids = [item.get("id") for item in public_net.get("firewalls", [])]
        inbound = [
            _normal_rule(rule)
            for firewall_id in firewall_ids
            for rule in firewalls.get(firewall_id, {}).get("rules", [])
            if rule.get("direction") == "in"
        ]
        server["public_ip"] = bool(
            public_net.get("ipv4", {}).get("ip") or public_net.get("ipv6", {}).get("ip")
        )
        server["firewall_attached"] = bool(firewall_ids)
        server["firewall_ids"] = firewall_ids
        server["inbound"] = inbound
        server["backup_enabled"] = bool(server.get("backup_window"))
        server["stateful"] = bool(server.get("volumes"))
        server["delete_protection"] = bool(server.get("protection", {}).get("delete"))
    return normalized


def _derive_edges(raw: dict[str, list[dict[str, Any]]]) -> list[Edge]:
    edges: list[Edge] = []
    servers = {server.get("id"): server for server in raw.get("server", [])}
    networks = {network.get("id"): network for network in raw.get("network", [])}
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
    for server_id, server in servers.items():
        sid = f"hcloud:server:{server_id}"
        for rule in server.get("inbound", []):
            protocol = str(rule.get("protocol", "tcp"))
            port = rule.get("port") if isinstance(rule.get("port"), int) else None
            evidence = (
                Evidence("hcloud_api", "firewall_rule", sid, rule, "properties.inbound"),
            )
            if set(rule.get("sources", [])) & {"0.0.0.0/0", "::/0"}:
                edges.append(Edge("internet", sid, "allows", protocol, port, evidence))
        # Hetzner Cloud Firewalls do not filter private network traffic, so every attached
        # server accepts every port from the network until a host firewall says otherwise.
        # https://docs.hetzner.com/cloud/firewalls/faq/
        for private_net in server.get("private_net", []):
            network_id = private_net.get("network")
            if network_id not in networks:
                continue
            edges.append(
                Edge(
                    f"hcloud:network:{network_id}",
                    sid,
                    "allows",
                    None,
                    None,
                    (
                        Evidence(
                            "hcloud_api",
                            "private_network_unfiltered",
                            sid,
                            {
                                "network": network_id,
                                "ip": private_net.get("ip"),
                                "cloud_firewall_applies": False,
                            },
                            "properties.private_net",
                        ),
                    ),
                )
            )
    return edges


def _derive_facts(
    assets: list[Asset], observed_at: str, run_id: str
) -> list[Fact]:
    facts: list[Fact] = []
    for asset in assets:
        for key, value in sorted(asset.properties.items()):
            if key in {"prices", "metrics"} or isinstance(value, (str, int, float, bool, type(None), list, dict)):
                identity = f"{asset.id}\x00{key}"
                fact_id = "fact-" + hashlib.sha256(identity.encode()).hexdigest()[:20]
                facts.append(
                    Fact(
                        id=fact_id,
                        kind=key,
                        asset_id=asset.id,
                        value=value,
                        source=asset.source,
                        observed_at=observed_at,
                        collector_version=COLLECTOR_VERSION,
                        run_id=run_id,
                        path=f"properties.{key}",
                    )
                )
    return facts
