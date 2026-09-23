"""Minimal read-only Hetzner Cloud API collector.

The module intentionally implements only HTTP GET and exposes no generic request method.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from typing import Any

from ..models import Asset, Edge, Evidence, Fact, Snapshot

API_BASE = "https://api.hetzner.cloud/v1"
HETZNER_API_BASE = "https://api.hetzner.com/v1"
COLLECTOR_VERSION = "0.8.0"
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

# Action history per resource family; read newest first and only back to ACTION_WINDOW_DAYS.
ACTION_ENDPOINTS = {
    "server": "servers/actions",
    "firewall": "firewalls/actions",
    "volume": "volumes/actions",
    "floating_ip": "floating_ips/actions",
    "primary_ip": "primary_ips/actions",
    "load_balancer": "load_balancers/actions",
    "network": "networks/actions",
    "image": "images/actions",
    "certificate": "certificates/actions",
    "storage_box": "hetzner:storage_boxes/actions",
}
ACTION_WINDOW_DAYS = 30
ACTION_MAX_PAGES = 10

MAX_ATTEMPTS = 4
MAX_PAGES = 1000  # 50 per page: far above any real project, but bounded
RETRY_STATUSES = {429, 500, 502, 503, 504}


def _retry_delay(attempt: int, retry_after: str | None) -> float:
    """Honor Retry-After (capped at 30 s); otherwise exponential backoff with jitter."""
    if retry_after:
        try:
            return min(max(float(retry_after), 0.0), 30.0)
        except ValueError:
            pass
    return float(2 ** (attempt - 1)) * (0.5 + random.random() / 2)  # noqa: S311 -- jitter, not crypto


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
        self._urlopen: Any = urllib.request.urlopen  # injectable for tests
        self._sleep: Any = time.sleep
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
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                with self._urlopen(request, timeout=30) as response:
                    payload: Any = json.loads(response.read())
                    if not isinstance(payload, dict):
                        raise HCloudCollectionError(f"unexpected response shape for {endpoint}")
                    return {str(key): value for key, value in payload.items()}
            except urllib.error.HTTPError as exc:
                if exc.code not in RETRY_STATUSES or attempt == MAX_ATTEMPTS:
                    raise HCloudCollectionError(
                        f"read-only GET failed for {endpoint}: HTTP {exc.code}", status=exc.code
                    ) from exc
                self._sleep(_retry_delay(attempt, exc.headers.get("Retry-After") if exc.headers else None))
            except HCloudCollectionError:
                raise
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                if attempt == MAX_ATTEMPTS:
                    raise HCloudCollectionError(f"read-only GET failed for {endpoint}: {exc}") from exc
                self._sleep(_retry_delay(attempt, None))
            except Exception as exc:
                raise HCloudCollectionError(f"read-only GET failed for {endpoint}: {exc}") from exc
        raise HCloudCollectionError(f"read-only GET failed for {endpoint}: retries exhausted")

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
            if page > MAX_PAGES:
                raise HCloudCollectionError(f"pagination for {endpoint} exceeded {MAX_PAGES} pages")
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
        signals = self._collect_actions(coverage, collected_at)
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
            for rrset in map(_minimize_rrset, self._list(f"zones/{zone_id}/rrsets", "rrsets")):
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
        for endpoint in sorted({edge.target for edge in edges if edge.target.startswith("endpoint:ip:")}):
            address = endpoint.removeprefix("endpoint:ip:")
            assets.append(Asset(endpoint, "endpoint", address, {"ip": address, "resolved": False,
                                                               "note": "load balancer target outside this project's servers"}, {}, "hcloud_api"))
        facts = _derive_facts(assets, collected_at, run_id)
        return Snapshot(
            assets=assets,
            edges=edges,
            facts=facts,
            signals=signals,
            metadata={
                "collector": "hcloud_api",
                "collector_version": COLLECTOR_VERSION,
                "run_id": run_id,
                "read_only": True,
                "collected_at": collected_at,
                "coverage": coverage,
            },
        )

    def _collect_actions(self, coverage: dict[str, dict[str, object]], collected_at: str) -> list[dict[str, Any]]:
        """Recent provider actions (newest first) as change signals; history is evidence of drift."""
        cutoff = datetime.fromisoformat(collected_at) - timedelta(days=ACTION_WINDOW_DAYS)
        signals: list[dict[str, Any]] = []
        failed: list[str] = []
        truncated: list[str] = []
        for kind, endpoint in ACTION_ENDPOINTS.items():
            base_url = self.base_url
            path = endpoint
            if endpoint.startswith("hetzner:"):
                path, base_url = endpoint.removeprefix("hetzner:"), HETZNER_API_BASE
            try:
                for page in range(1, ACTION_MAX_PAGES + 1):
                    payload = self._get_json(path, {"page": page, "per_page": 50, "sort": "started:desc"}, base_url=base_url)
                    rows = payload.get("actions", []) or []
                    recent = [row for row in rows if (started := _action_time(row)) is not None and started >= cutoff]
                    signals.extend(_action_signal(row, kind) for row in recent)
                    if len(recent) < len(rows) or not payload.get("meta", {}).get("pagination", {}).get("next_page"):
                        break
                else:
                    truncated.append(kind)  # page cap reached inside the window: history is incomplete
            except HCloudCollectionError:
                failed.append(kind)
        coverage["actions"] = {
            "status": "collected" if not failed and not truncated else "partial",
            "count": len(signals),
            "window_days": ACTION_WINDOW_DAYS,
            **({"failed": failed} if failed else {}),
            **({"truncated": truncated} if truncated else {}),
        }
        return signals

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


# Record values the rules read. Other record types (TXT, MX, CAA, SRV, …) keep name, type, and count:
# TXT values often carry verification tokens or ACME challenges that no rule needs.
DNS_VALUE_TYPES = {"A", "AAAA", "CNAME"}


def _minimize_rrset(rrset: dict[str, Any]) -> dict[str, Any]:
    if str(rrset.get("type", "")).upper() in DNS_VALUE_TYPES:
        return rrset
    records = rrset.get("records") or []
    return {**rrset, "records": [], "record_count": len(records), "values_omitted": True}


def _action_time(row: dict[str, Any]) -> datetime | None:
    value = row.get("started")
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _action_signal(row: dict[str, Any], family: str) -> dict[str, Any]:
    resources = [item for item in row.get("resources") or [] if isinstance(item, dict)]
    error = row.get("error")
    return {
        "type": "provider_action",
        "id": row.get("id"),
        "family": family,
        "command": row.get("command"),
        "status": row.get("status"),
        "started": row.get("started"),
        "finished": row.get("finished"),
        "resources": [{"id": item.get("id"), "type": item.get("type")} for item in resources],
        "asset_ids": [f"hcloud:{item.get('type')}:{item.get('id')}" for item in resources],
        "error": error.get("code") if isinstance(error, dict) else None,  # the message can echo input
    }


EMAIL_PATTERN = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
# Storage Box hostnames embed the account ID (u123456.your-storagebox.de).
STORAGE_BOX_HOST_PATTERN = re.compile(r"\bu\d+(?:-sub\d+)?\.your-storagebox\.de\b")
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
    if lowered == "certificate" and isinstance(value, str) and "BEGIN CERTIFICATE" in value:
        # Public, but bulky and often names the organization; validity dates stay as fields.
        return "[certificate PEM omitted]"
    if isinstance(value, dict):
        return {str(k): _sanitize_resource(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_resource(item, key) for item in value]
    if isinstance(value, str):
        value = STORAGE_BOX_HOST_PATTERN.sub("[REDACTED:storage-box-host]", value)
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


STATEFUL_ROLES = {
    "db", "database", "pg", "sql", "postgres", "postgresql", "mysql", "mariadb", "redis", "mongo", "mongodb",
    "replica", "warehouse", "storage", "data", "vault", "queue", "kafka", "rabbitmq", "elastic",
    "elasticsearch", "clickhouse", "minio", "backup",
}


def _is_stateful(server: dict[str, Any]) -> bool:
    """Attached volumes, a stateful role, or an explicit stateful=true label; stateful=false wins."""
    labels = {str(k).lower(): str(v).lower() for k, v in (server.get("labels") or {}).items()}
    if labels.get("stateful") in {"true", "false"}:
        return labels["stateful"] == "true"
    words = set()
    for value in (labels.get("role", ""), labels.get("service", ""), str(server.get("name", "")).lower()):
        words |= set(value.replace("_", "-").split("-"))
    return bool(server.get("volumes")) or bool(words & STATEFUL_ROLES)


def _ssh_key_strength(public_key: object) -> tuple[str | None, int | None]:
    """Key algorithm and size from an OpenSSH public key, computed before the key is redacted."""
    if not isinstance(public_key, str) or not public_key.strip():
        return None, None
    parts = public_key.split()
    key_type = parts[0]
    if key_type == "ssh-ed25519":
        return key_type, 256
    if key_type.startswith("ecdsa-sha2-nistp"):
        return key_type, int(key_type.removeprefix("ecdsa-sha2-nistp") or 0) or None
    if key_type in {"ssh-rsa", "ssh-dss"} and len(parts) > 1:
        try:
            blob = base64.b64decode(parts[1])
            fields: list[bytes] = []
            offset = 0
            while offset + 4 <= len(blob) and len(fields) < 3:
                length = int.from_bytes(blob[offset : offset + 4], "big")
                fields.append(blob[offset + 4 : offset + 4 + length])
                offset += 4 + length
            if key_type == "ssh-rsa" and len(fields) == 3:
                return key_type, int.from_bytes(fields[2], "big").bit_length()
            if key_type == "ssh-dss" and len(fields) >= 2:
                return key_type, int.from_bytes(fields[1], "big").bit_length()
        except (ValueError, IndexError):
            return key_type, None
    return key_type, None


def _normalize_resources(
    raw: dict[str, list[dict[str, Any]]],
) -> dict[str, list[dict[str, Any]]]:
    normalized = {kind: [dict(row) for row in rows] for kind, rows in raw.items()}
    firewalls = {row.get("id"): row for row in raw.get("firewall", [])}
    for firewall in normalized.get("firewall", []):
        firewall["inbound"] = [
            _normal_rule(rule) for rule in firewall.get("rules", []) if rule.get("direction") == "in"
        ]
        firewall["outbound"] = [
            _normal_rule(rule) for rule in firewall.get("rules", []) if rule.get("direction") == "out"
        ]
    for key in normalized.get("ssh_key", []):
        key["key_type"], key["key_bits"] = _ssh_key_strength(key.get("public_key"))
    for server in normalized.get("server", []):
        public_net = server.get("public_net", {})
        firewall_ids = [item.get("id") for item in public_net.get("firewalls", [])]
        inbound = [
            _normal_rule(rule)
            for firewall_id in firewall_ids
            for rule in firewalls.get(firewall_id, {}).get("rules", [])
            if rule.get("direction") == "in"
        ]
        server["public_ipv4"] = bool((public_net.get("ipv4") or {}).get("ip"))
        server["public_ipv6"] = bool((public_net.get("ipv6") or {}).get("ip"))
        server["public_ip"] = server["public_ipv4"] or server["public_ipv6"]
        # Hetzner semantics: without any outbound rule, all egress is allowed; with one, the rest is denied.
        server["outbound"] = [
            _normal_rule(rule)
            for firewall_id in firewall_ids
            for rule in firewalls.get(firewall_id, {}).get("rules", [])
            if rule.get("direction") == "out"
        ]
        server["firewall_attached"] = bool(firewall_ids)
        server["firewall_ids"] = firewall_ids
        server["inbound"] = inbound
        server["backup_enabled"] = bool(server.get("backup_window"))
        server["stateful"] = _is_stateful(server)
        server["delete_protection"] = bool(server.get("protection", {}).get("delete"))
    return normalized


def _derive_edges(raw: dict[str, list[dict[str, Any]]]) -> list[Edge]:
    edges: list[Edge] = []
    address_owner: dict[str, Any] = {}
    for server in raw.get("server", []):
        public_net = server.get("public_net") or {}
        for family in ("ipv4", "ipv6"):
            ip = (public_net.get(family) or {}).get("ip")
            if ip:
                address_owner[str(ip).split("/")[0]] = server.get("id")
        for private_net in server.get("private_net") or []:
            if private_net.get("ip"):
                address_owner[str(private_net["ip"])] = server.get("id")
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
            # A world rule admits Internet traffic only over a family the server has a public address in.
            reachable = {"0.0.0.0/0"} if server.get("public_ipv4") else set()
            reachable |= {"::/0"} if server.get("public_ipv6") else set()
            if set(rule.get("sources", [])) & reachable:
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
    # Load balancers forward Internet traffic: listen port on the LB, destination port on each target.
    for lb in raw.get("load_balancer", []):
        lid = f"hcloud:load_balancer:{lb.get('id')}"
        public = bool((lb.get("public_net") or {}).get("enabled", True))
        services = lb.get("services") or []
        target_servers: list[tuple[Any, bool]] = []
        target_ips: list[str] = []
        for target in lb.get("targets") or []:
            if target.get("type") == "ip" and (target.get("ip") or {}).get("ip"):
                target_ips.append(str(target["ip"]["ip"]))
            if target.get("type") == "server" and (target.get("server") or {}).get("id") is not None:
                target_servers.append((target["server"]["id"], bool(target.get("use_private_ip"))))
            for nested in target.get("targets") or []:  # label_selector targets resolve to servers
                if (nested.get("server") or {}).get("id") is not None:
                    target_servers.append((nested["server"]["id"], bool(nested.get("use_private_ip"))))
        for service in services:
            listen, destination = service.get("listen_port"), service.get("destination_port")
            evidence = (Evidence("hcloud_api", "load_balancer_service", lid, service, "properties.services"),)
            if public and isinstance(listen, int):
                edges.append(Edge("internet", lid, "allows", "tcp", listen, evidence))
            if isinstance(destination, int):
                # IP targets: a known Cloud server's address resolves to that server; anything else
                # (a Robot dedicated server, an external host) stays an explicit endpoint, never dropped.
                for address in target_ips:
                    resolved = address_owner.get(address)
                    edges.append(
                        Edge(
                            lid,
                            f"hcloud:server:{resolved}" if resolved is not None else f"endpoint:ip:{address}",
                            "allows",
                            "tcp",
                            destination,
                            (Evidence("hcloud_api", "load_balancer_target", lid, {"ip": address, "port": destination}, "properties.targets"),),
                        )
                    )
                for server_id, private in target_servers:
                    edges.append(
                        Edge(
                            lid,
                            f"hcloud:server:{server_id}",
                            "allows",
                            "tcp",
                            destination,
                            (Evidence("hcloud_api", "load_balancer_target", lid, {"server": server_id, "use_private_ip": private, "port": destination}, "properties.targets"),),
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
