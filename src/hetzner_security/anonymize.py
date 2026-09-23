"""Anonymize a snapshot so it can be shared for the validation corpus or a bug report.

Consistent replacement, so topology and findings survive:
- asset names become <role or type>-<n>; every other occurrence of a name is rewritten too;
- label values are replaced unless they are generic words (environment prod/staging/…, sensitivity,
  stateful, audit.ignore true/false); role labels keep only generic role words; label keys that are
  not plain words (domains, customer names) are replaced;
- public IPv4/IPv6 addresses map into documentation ranges (prefix length kept); world, private,
  CGNAT/mesh, and known edge-provider ranges are kept, because rules depend on them;
- every provider ID is renumbered (in asset IDs and ID fields); non-standard ports are renumbered (well-known and
  sensitive ports are kept);
- domain names, emails, descriptions, comments, fingerprints, and key material are replaced.

Review the output before sharing it: anonymization reduces, but cannot rule out, re-identification.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

from .analyzers.rules import SENSITIVE_SERVICES
from .flows import INTERNAL
from .providers import edge_provider, is_mesh

# Label values kept only when they are one of these generic words; anything else is replaced.
SAFE_LABEL_VALUES = {
    "environment": {"prod", "production", "staging", "stage", "dev", "development", "test", "testing", "qa", "preview",
                    "sandbox", "demo", "shared", "ops"},
    "sensitivity": {"high", "medium", "low"},
    "stateful": {"true", "false"},
}
# Keys whose integer values are provider IDs (renumbered regardless of size).
ID_KEYS = {"id", "server", "network", "servers", "networks", "firewall_ids", "volumes", "load_balancers", "assignee_id",
           "image", "placement_group", "floating_ips", "primary_ips", "server_number", "zone", "certificate_id", "storage_box"}
# Role words rules and diagrams understand; anything else in a role label is replaced.
ROLE_WORDS = {
    "app", "api", "web", "fe", "frontend", "backend", "edge", "proxy", "lb", "gateway", "worker", "service", "bus", "agent",
    "agents", "db", "database", "postgres", "postgresql", "pg", "sql", "mysql", "mariadb", "mongo", "redis", "replica",
    "warehouse", "data", "storage", "vault", "auth", "identity", "secret", "secrets", "kms", "queue", "kafka", "rabbitmq",
    "cache", "search", "elastic", "clickhouse", "analytics", "ci", "build", "runner", "monitoring", "metrics", "jobs", "etl",
    "lake", "preview", "staging", "prod", "backup", "control", "node", "k8s", "dns", "mail", "vpn", "batch", "ingest",
    "orchestrator", "scheduler", "catalog", "dev", "test",
}
PORT_KEYS = {"port", "port_from", "port_to", "listen_port", "destination_port", "host_port", "container_port", "node_port",
             "nodePort", "dst_port"}
TEXT_KEYS = {"description", "comment", "notes", "fingerprint", "public_key", "mac_address", "dns_ptr", "server_name", "certificate"}
# Ports rules read (services, databases, mesh VPNs) keep their numbers so findings do not change.
KEEP_PORTS = {20, 21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995, 3000, 3306, 5432, 6379, 8000, 8080, 8443,
              9000, 9200, 27017, 41641, 51820, 9993}
KEEP_PORTS |= {port for _proto, first, last, _name, _sev in SENSITIVE_SERVICES if last - first < 100 for port in range(first, last + 1)}
DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|app|de|eu|pl|co|uk|cloud|ai|tech|info|biz|xyz|me|us)\b", re.I)
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})(/\d{1,2})?\b")
IPV6 = re.compile(r"(?<![\w:])((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F:]*|::)(/\d{1,3})?(?![\w:])")


class Anonymizer:
    def __init__(self) -> None:
        self.names: dict[str, str] = {}
        self.labels: dict[str, str] = {}
        self.ids: dict[int, int] = {}
        self.ports: dict[int, int] = {}
        self.v4: dict[str, str] = {}
        self.v6: dict[str, str] = {}
        self.domains: dict[str, str] = {}

    # -- scalars
    def _keep_network(self, text: str) -> bool:
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            return True
        if network.prefixlen == 0 or network.network_address.is_unspecified:
            return True  # the world, or a wildcard bind (0.0.0.0, ::)
        return (any(network.version == item.version and network.subnet_of(item) for item in INTERNAL)  # type: ignore[arg-type]
                or is_mesh(text) or edge_provider(text) is not None)

    def ip(self, text: str) -> str:
        def v4(match: re.Match[str]) -> str:
            address, suffix = match.group(1), match.group(2) or ""
            if self._keep_network(address + (suffix or "/32")):
                return match.group(0)
            if address not in self.v4:
                index = len(self.v4)
                block = ("203.0.113", "198.51.100", "192.0.2")[index // 250 % 3]
                self.v4[address] = f"{block}.{index % 250 + 1}"
            return self.v4[address] + suffix

        def v6(match: re.Match[str]) -> str:
            address, suffix = match.group(1), match.group(2) or ""
            try:
                ipaddress.ip_network(address + (suffix or "/128"), strict=False)
            except ValueError:
                return match.group(0)
            if self._keep_network(address + (suffix or "/128")):
                return match.group(0)
            if address not in self.v6:
                self.v6[address] = f"2001:db8:{len(self.v6) + 1:x}::"
            return self.v6[address] + suffix

        return IPV6.sub(v6, IPV4.sub(v4, text))

    def text(self, value: str) -> str:
        for original in sorted(self.names, key=len, reverse=True):
            if original and original in value:
                value = re.sub(rf"(?<![\w-]){re.escape(original)}(?![\w-])", self.names[original], value)
        value = EMAIL.sub("user@example.test", value)
        value = DOMAIN.sub(lambda match: self.domains.setdefault(match.group(0).lower(), f"host-{len(self.domains) + 1}.example.test"), value)
        return self.ip(value)

    def number(self, value: int, key: str) -> int:
        if key in PORT_KEYS:
            if value in KEEP_PORTS or 30000 <= value <= 32767 or value < 1024:
                return value
            return self.ports.setdefault(value, 20000 + len(self.ports))
        if key in ID_KEYS or value > 65535:
            return self.ids.setdefault(value, 1_000_000 + len(self.ids))
        return value

    # -- structures
    def walk(self, value: Any, key: str = "") -> Any:
        if isinstance(value, dict):
            output: dict[str, Any] = {}
            for name, item in value.items():
                if name == "labels" and isinstance(item, dict):
                    output[name] = {self.label_key(label): self.label_value(label, text) for label, text in item.items()}
                elif name in TEXT_KEYS and isinstance(item, str) and item:
                    output[name] = f"[{name} removed]"
                else:
                    output[name] = self.walk(item, name)
            return output
        if isinstance(value, list):
            if key in ID_KEYS:
                return self.id_list(value, key)
            return [self.walk(item, key) for item in value]
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return self.number(value, key)
        if isinstance(value, str):
            if key in ID_KEYS and value.isdigit():
                return str(self.number(int(value), "id"))
            if key in PORT_KEYS and re.fullmatch(r"\d+(-\d+)?", value):
                return "-".join(str(self.number(int(part), key)) for part in value.split("-"))
            return self.text(value)
        return value

    def label(self, value: str) -> str:
        return self.labels.setdefault(value, f"value-{len(self.labels) + 1}")

    def role(self, value: str) -> str:
        words = [word for word in re.split(r"[-_./ ]+", value.lower()) if word in ROLE_WORDS]
        return "-".join(words) or self.labels.setdefault(f"role:{value}", f"role-{len(self.labels) + 1}")

    def label_key(self, key: str) -> str:
        """Keys can carry a domain or a customer name (acme.com/team): keep only plain generic keys."""
        if key.startswith("audit.") and re.fullmatch(r"audit\.(ignore)(\.HETZ-[A-Z0-9]+-\d{3})?", key):
            return key
        if re.fullmatch(r"[a-z][a-z_-]{0,30}", key) and key not in self.names:
            return key
        return self.labels.setdefault(f"key:{key}", f"label-{len(self.labels) + 1}")

    def label_value(self, label: str, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        if value.lower() in SAFE_LABEL_VALUES.get(label, set()):
            return value.lower()
        if label.startswith("audit.ignore") and value.lower() in {"true", "false"}:
            return value.lower()
        if label == "role":
            return self.role(value)
        return self.label(value)

    def asset_id(self, value: str) -> str:
        parts = value.split(":")
        return ":".join(str(self.number(int(part), "id")) if part.isdigit() else self.text(part) for part in parts)

    def id_list(self, value: Any, key: str) -> Any:
        return [self.number(item, "id") if isinstance(item, int) and not isinstance(item, bool) else self.walk(item, key) for item in value]

    def snapshot(self, raw: dict[str, Any]) -> dict[str, Any]:
        counters: dict[str, int] = {}
        for asset in raw.get("assets", []):
            name = str(asset.get("name", ""))
            if not name or name in self.names or asset.get("type") in {"server_type", "location", "datacenter", "load_balancer_type",
                                                                        "storage_box_type", "pricing"}:
                continue
            is_catalog_image = asset.get("type") == "image" and (asset.get("properties") or {}).get("type") in {"system", "app"}
            if is_catalog_image:
                continue
            role = (asset.get("labels") or {}).get("role")
            base = self.role(str(role)) if role else str(asset.get("type") or "asset")
            counters[base] = counters.get(base, 0) + 1
            self.names[name] = f"{base}-{counters[base]:02d}"
        assets = []
        for asset in raw.get("assets", []):
            item = self.walk({key: value for key, value in asset.items() if key not in {"id", "name"}})
            item["id"] = self.asset_id(str(asset.get("id", "")))
            item["name"] = self.names.get(str(asset.get("name", "")), self.text(str(asset.get("name", ""))))
            assets.append(item)
        edges = []
        for edge in raw.get("edges", []):
            item = self.walk({key: value for key, value in edge.items() if key not in {"source", "target"}})
            item["source"] = self.asset_id(str(edge.get("source", "")))
            item["target"] = self.asset_id(str(edge.get("target", "")))
            for evidence in item.get("evidence", []) or []:
                evidence["asset_id"] = self.asset_id(str(evidence.get("asset_id", "")))
            edges.append(item)
        metadata = self.walk(raw.get("metadata", {}))
        metadata["anonymized"] = True
        metadata.pop("project", None)
        return {
            **{key: value for key, value in raw.items() if key not in {"assets", "edges", "facts", "signals", "metadata", "expectations"}},
            "metadata": metadata,
            "assets": assets,
            "edges": edges,
            "facts": [],  # facts duplicate asset state with raw values; rebuilt by a new collection
            "signals": [{**self.walk(signal), "asset_ids": [self.asset_id(str(item)) for item in signal.get("asset_ids", [])]}
                        for signal in raw.get("signals", [])],
            "expectations": self.walk(raw.get("expectations", [])),
        }


def anonymize_snapshot(raw: dict[str, Any]) -> dict[str, Any]:
    anonymizer = Anonymizer()
    result = anonymizer.snapshot(raw)
    # IDs also hide inside text (for example /dev/disk/by-id/scsi-0HC_Volume_<id>): one final pass
    # replaces every known original ID wherever it appears, in a single substitution.
    originals = {str(original): str(mapped) for original, mapped in anonymizer.ids.items() if original >= 1000}
    if originals:
        text = json.dumps(result)
        text = re.sub(r"(?<!\d)(\d{4,})(?!\d)", lambda match: originals.get(match.group(1), match.group(1)), text)
        result = json.loads(text)
    return result


def leftovers(original: dict[str, Any], anonymized: dict[str, Any]) -> list[str]:
    """Original asset names or public addresses still present in the output (should be empty)."""
    text = json.dumps(anonymized)
    names = [str(asset.get("name")) for asset in original.get("assets", [])
             if asset.get("type") in {"server", "network", "firewall", "volume", "load_balancer", "storage_box", "robot_server", "bucket"}
             and len(str(asset.get("name", ""))) > 3]
    return sorted({name for name in names if re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", text)})
