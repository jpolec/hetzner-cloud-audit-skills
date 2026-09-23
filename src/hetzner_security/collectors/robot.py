"""Read-only Hetzner Robot collector: dedicated servers, Robot firewall, vSwitch, and SSH keys.

Robot is a separate API (robot-ws.your-server.de) with HTTP Basic auth for a webservice user,
created under Robot → Settings → Webservice and app settings. The client sends GET only. The
same normalization also reads a saved file of Robot responses (``--robot FILE``) for offline
audits and tests.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from dataclasses import replace
from typing import Any

from ..flows import PortSet
from ..models import Asset, Edge, Evidence, Snapshot
from .hcloud import _sanitize_resource, _ssh_key_strength

ROBOT_BASE = "https://robot-ws.your-server.de"
MAX_ROBOT_BYTES = 32 * 1024 * 1024
ROBOT_KEY_TYPES = {"RSA": "ssh-rsa", "DSA": "ssh-dss", "ED25519": "ssh-ed25519", "ECDSA": "ecdsa-sha2-nistp256"}


class RobotCollectionError(RuntimeError):
    pass


class ReadOnlyRobotCollector:
    """GET-only Robot client. Credentials come from HROBOT_USER and HROBOT_PASSWORD."""

    def __init__(self, user: str | None = None, password: str | None = None, *, base_url: str = ROBOT_BASE) -> None:
        user = user or os.environ.get("HROBOT_USER")
        password = password or os.environ.get("HROBOT_PASSWORD")
        if not user or not password:
            raise RobotCollectionError("HROBOT_USER and HROBOT_PASSWORD (a Robot webservice user) are required")
        self._auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self._urlopen: Any = urllib.request.urlopen
        self.base_url = base_url.rstrip("/")

    def _get(self, path: str) -> Any:
        request = urllib.request.Request(  # noqa: S310 -- fixed HTTPS Robot base by default
            f"{self.base_url}/{path}", headers={"Authorization": self._auth, "Accept": "application/json"}, method="GET"
        )
        try:
            with self._urlopen(request, timeout=30) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None  # Robot answers 404 for "no firewall" / "no vSwitch"
            raise RobotCollectionError(f"read-only GET failed for {path}: HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            raise RobotCollectionError(f"read-only GET failed for {path}: {exc}") from exc

    def fetch(self) -> dict[str, Any]:
        """Raw Robot responses, keyed like the file format ``--robot`` reads."""
        servers = self._get("server") or []
        firewalls = {}
        for item in servers:
            number = (item.get("server") or {}).get("server_number")
            if number is not None:
                try:
                    firewalls[str(number)] = self._get(f"firewall/{number}")
                except RobotCollectionError as exc:
                    firewalls[str(number)] = {"error": str(exc)}  # unknown, not "no firewall"
        errors: list[str] = []
        vswitches: list[Any] = []
        keys: list[Any] = []
        try:
            vswitches = [self._get(f"vswitch/{item.get('id')}") for item in (self._get("vswitch") or []) if item.get("id") is not None]
        except RobotCollectionError as exc:
            errors.append(f"vswitch: {exc}")
        try:
            keys = self._get("key") or []
        except RobotCollectionError as exc:
            errors.append(f"key: {exc}")
        return {"server": servers, "firewall": firewalls, "vswitch": [item for item in vswitches if item], "key": keys, "errors": errors}


def load_robot_file(path: Any) -> dict[str, Any]:
    if path.stat().st_size > MAX_ROBOT_BYTES:
        raise ValueError(f"Robot file {path} exceeds {MAX_ROBOT_BYTES} bytes")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or "server" not in raw:
        raise ValueError(f"{path} must hold Robot responses: {{'server': [...], 'firewall': {{...}}, 'vswitch': [...], 'key': [...]}}")
    return raw


def _ports(value: object) -> PortSet:
    text = str(value or "").strip()
    if not text:
        return PortSet.full()
    spans = []
    for piece in text.split(","):
        first, _, last = piece.strip().partition("-")
        if first.isdigit() and (not last or last.isdigit()):
            spans.append((int(first), int(last or first)))
    return PortSet.of(spans)


def robot_world_ports(rules: list[dict[str, Any]], protocol: str = "tcp", family: str = "ipv4") -> PortSet:
    """Ports the Robot firewall admits to a new connection from any source; first match wins, default discard.

    A rule only decides a plain SYN from anywhere when it has no source restriction, no TCP flag
    other than "syn", and no source-port or destination-IP match. A narrower discard therefore
    cannot hide a later accept, and ACK-only accepts (return traffic) never admit a connection.
    """
    decided, allowed = PortSet(), PortSet()
    for rule in rules:
        if rule.get("ip_version") not in (None, "", family):
            continue
        if rule.get("src_ip") not in (None, "", "0.0.0.0/0", "::/0"):
            continue  # a specific source does not admit the whole Internet
        if rule.get("protocol") not in (None, "", protocol):
            continue
        flags = str(rule.get("tcp_flags") or "").lower().replace(" ", "")
        if flags and flags != "syn":
            continue
        if (rule.get("src_port") or rule.get("dst_ip")) and rule.get("action") != "accept":
            continue
        fresh = _ports(rule.get("dst_port")).difference(decided)
        if rule.get("action") == "accept":
            allowed = allowed.union(fresh)
        decided = decided.union(fresh)
    return allowed


def robot_exposure(firewall: dict[str, Any], protocol: str = "tcp") -> PortSet:
    """IPv4 plus, when the firewall filters it, IPv6 (unfiltered IPv6 is HETZ-ROB-005)."""
    rules = firewall.get("rules") or []
    ports = robot_world_ports(rules, protocol, "ipv4")
    if firewall.get("filter_ipv6"):
        ports = ports.union(robot_world_ports(rules, protocol, "ipv6"))
    return ports


def _firewall_rules(firewall: dict[str, Any]) -> list[dict[str, Any]]:
    rules = firewall.get("rules") or {}
    return list(rules.get("input") or []) if isinstance(rules, dict) else []


def normalize_robot(raw: dict[str, Any]) -> tuple[list[Asset], list[Edge], dict[str, Any]]:
    assets: list[Asset] = []
    edges: list[Edge] = []
    for item in raw.get("server") or []:
        server = item.get("server") or item
        number = server.get("server_number")
        if number is None:
            continue
        entry = (raw.get("firewall") or {}).get(str(number)) or {}
        firewall_error = entry.get("error") if isinstance(entry, dict) else None
        firewall = None if firewall_error else entry.get("firewall")
        props = {
            "server_number": number,
            "server_ip": server.get("server_ip"),
            "ip": server.get("ip") or ([server["server_ip"]] if server.get("server_ip") else []),
            "server_ipv6_net": server.get("server_ipv6_net"),
            "product": server.get("product"),
            "dc": server.get("dc"),
            "status": server.get("status"),
            "cancelled": server.get("cancelled"),
            "paid_until": server.get("paid_until"),
            "traffic": server.get("traffic"),
            "robot_firewall": {
                "present": None if firewall_error else firewall is not None,
                "status": "unknown" if firewall_error else (firewall or {}).get("status"),
                "filter_ipv6": (firewall or {}).get("filter_ipv6"),
                "whitelist_hos": (firewall or {}).get("whitelist_hos"),
                "rules": _firewall_rules(firewall or {}),
            },
        }
        asset = Asset(f"robot:server:{number}", "robot_server", str(server.get("server_name") or number),
                      _sanitize_resource(props), {}, "robot_api")
        assets.append(asset)
        if firewall_error:
            pass  # the firewall could not be read: no edge either way
        elif not firewall or firewall.get("status") != "active":
            edges.append(Edge("internet", asset.id, "allows", None, None,
                              (Evidence("robot_api", "robot_firewall", asset.id, {"status": (firewall or {}).get("status", "absent")}, "properties.robot_firewall"),)))
        else:
            for protocol in ("tcp", "udp"):
                for first, last in robot_exposure({**firewall, "rules": _firewall_rules(firewall)}, protocol):
                    observed = {"protocol": protocol, "port_from": first, "port_to": last, "sources": ["0.0.0.0/0"]}
                    edges.append(Edge("internet", asset.id, "allows", protocol, first if first == last else None,
                                      (Evidence("robot_api", "firewall_rule", asset.id, observed, "properties.robot_firewall.rules"),)))
    for vswitch in raw.get("vswitch") or []:
        vid = vswitch.get("id")
        asset = Asset(f"robot:vswitch:{vid}", "vswitch", str(vswitch.get("name") or vid), _sanitize_resource({
            "vlan": vswitch.get("vlan"), "cancelled": vswitch.get("cancelled"),
            "servers": [member.get("server_number") for member in vswitch.get("server") or []],
            "cloud_network": vswitch.get("cloud_network") or [],
        }), {}, "robot_api")
        assets.append(asset)
        for member in vswitch.get("server") or []:
            target = f"robot:server:{member.get('server_number')}"
            edges.append(Edge(asset.id, target, "allows", None, None,
                              (Evidence("robot_api", "vswitch_unfiltered", asset.id, member, "properties.servers"),)))
            edges.append(Edge(target, asset.id, "attached_to"))
        for network in vswitch.get("cloud_network") or []:
            network_id = f"hcloud:network:{network.get('id')}"
            evidence = (Evidence("robot_api", "vswitch_cloud_coupling", asset.id, network, "properties.cloud_network"),)
            edges.append(Edge(asset.id, network_id, "allows", None, None, evidence))
            edges.append(Edge(network_id, asset.id, "allows", None, None, evidence))
    for item in raw.get("key") or []:
        key = item.get("key") or item
        key_type, bits = _ssh_key_strength(key.get("data"))
        fingerprint = str(key.get("fingerprint") or key.get("name"))
        assets.append(Asset(f"robot:ssh_key:{fingerprint}", "ssh_key", str(key.get("name") or fingerprint), _sanitize_resource({
            "key_type": key_type or ROBOT_KEY_TYPES.get(str(key.get("type", "")).upper()),
            "key_bits": bits or key.get("size"),
            "created": key.get("created_at"),
            "fingerprint": key.get("fingerprint"),
        }), {}, "robot_api"))
    firewall_errors = [key for key, entry in (raw.get("firewall") or {}).items() if isinstance(entry, dict) and entry.get("error")]
    errors = [str(item) for item in raw.get("errors") or []]
    coverage = {
        "robot_server": {"status": "partial" if firewall_errors else "collected", "count": sum(1 for a in assets if a.type == "robot_server"),
                         **({"firewall_unreadable": firewall_errors} if firewall_errors else {})},
        "robot_vswitch": {"status": "partial" if any(item.startswith("vswitch") for item in errors) else "collected",
                          "count": sum(1 for a in assets if a.type == "vswitch")},
    }
    return assets, edges, coverage


def apply_robot(snapshot: Snapshot, raw: dict[str, Any]) -> Snapshot:
    assets, edges, coverage = normalize_robot(raw)
    known = {asset.id for asset in snapshot.assets}
    snapshot.assets.extend(asset for asset in assets if asset.id not in known)
    snapshot.edges.extend(edges)
    resolve_endpoints(snapshot)
    snapshot.metadata.setdefault("coverage", {}).update(coverage)
    return snapshot


def resolve_endpoints(snapshot: Snapshot) -> None:
    """Retarget load balancer IP targets that are Robot dedicated servers (hybrid LB -> dedicated)."""
    owners: dict[str, str] = {}
    for asset in snapshot.assets:
        if asset.type == "robot_server":
            for address in asset.properties.get("ip") or []:
                owners[str(address)] = asset.id
    moved = False
    for index, edge in enumerate(snapshot.edges):
        if edge.target.startswith("endpoint:ip:") and edge.target.removeprefix("endpoint:ip:") in owners:
            snapshot.edges[index] = replace(edge, target=owners[edge.target.removeprefix("endpoint:ip:")])
            moved = True
    if moved:
        targets = {edge.target for edge in snapshot.edges}
        snapshot.assets[:] = [asset for asset in snapshot.assets if asset.type != "endpoint" or asset.id in targets]
