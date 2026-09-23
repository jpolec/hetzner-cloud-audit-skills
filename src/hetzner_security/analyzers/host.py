"""Rules that need host evidence (``--host-bundle``): Docker firewall bypass, sshd, host firewall,
wide binds, container isolation, and PostgreSQL first-match authentication.

Without a bundle these rules stay silent: absence of host evidence is a coverage gap, not a finding.
"""

from __future__ import annotations

from ..flows import PortSet, asset_exposure, port_set
from ..graph import AttackGraph
from ..host.parsers import pg_remote_decisions
from ..models import Asset, Finding, Severity, Snapshot
from .rules import SENSITIVE_SERVICES, _candidate, _evidence

# Data and control-plane ports that should bind to a private or loopback address.
DATA_PORTS = {5432: "PostgreSQL", 6379: "Redis", 3306: "MySQL/MariaDB", 27017: "MongoDB", 9200: "Elasticsearch",
              **{first: name for proto, first, last, name, _ in SENSITIVE_SERVICES if proto == "tcp" and first == last}}
DATA_PORTS.pop(22, None)


def _hosts(snapshot: Snapshot) -> list[Asset]:
    return [asset for asset in snapshot.assets if asset.type == "server" and asset.properties.get("host_evidence")]


def _cloud_world(server: Asset, snapshot: Snapshot, protocol: str) -> PortSet:
    props = server.properties
    if props.get("public_ip", True) and props.get("firewall_attached") is False:
        return PortSet.full()
    exposure = asset_exposure(server, snapshot.edges)
    return PortSet.of(
        [span for (_family, proto, klass), ports in exposure.items() if proto == protocol and klass == "world" for span in ports]
    )


def docker_firewall_bypass(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    """HETZ-DKR-005: Docker publishes on a public bind, where the host firewall does not apply."""
    output: list[Finding] = []
    for server in _hosts(snapshot):
        props = server.properties
        firewall = props.get("host_firewall") or {}
        if not firewall.get("active") or not firewall.get("known", True):
            continue  # nothing to bypass (HETZ-HOST-001), or the host firewall's answer is unknown
        published = [item for item in props.get("docker_published") or [] if item.get("bind") in {"wildcard", "public"}]
        if not published:
            continue
        # Ports the host firewall itself admits from the world (without the Docker contribution).
        world_rules = port_set(firewall.get("world_tcp_ranges"))
        bypass = [item for item in published if item["protocol"] == "tcp" and item["host_port"] not in world_rules]
        if not bypass:
            continue
        ports = sorted({item["host_port"] for item in bypass})
        exposed = [port for port in ports if port in _cloud_world(server, snapshot, "tcp")]
        filtered = props.get("docker_user_filters")
        containers = sorted({str(item.get("container")) for item in bypass})
        if exposed:
            severity, title = Severity.HIGH, "Docker-published ports bypass the host firewall and are open to the Internet"
            impact = f"Ports {exposed} are reachable from the Internet even though the host firewall does not allow them."
        else:
            severity, title = Severity.MEDIUM, "Docker-published ports bypass the host firewall; only the Cloud Firewall protects them"
            impact = "A Cloud Firewall detach, rule edit, or new public IP exposes these ports; the host firewall will not stop it."
        evidence = [
            _evidence(server, "docker_published", bypass, "properties.docker_published"),
            _evidence(server, "host_firewall_decision", {"engine": firewall.get("engine"), "world_tcp": firewall.get("world_tcp")}, "properties.host_firewall"),
        ]
        if filtered:
            evidence.append(_evidence(server, "docker_user_chain", {"filters": True}, "properties.docker_user_filters"))
        output.append(
            _candidate(
                "HETZ-DKR-005",
                title,
                severity,
                0.93,
                [server.id],
                f"Containers {containers} publish ports {ports} on all interfaces; Docker's DNAT runs before {firewall.get('engine')} input rules.",
                "Containers publish on 127.0.0.1 or a private address, or DOCKER-USER rules restrict published ports.",
                f"Published on 0.0.0.0/[::]: {ports}; host firewall admits from the Internet: {firewall.get('world_tcp') or 'nothing'}.",
                evidence,
                ["internet", *(f"tcp/{port}" for port in ports[:3]), server.id],
                ["The cloud firewall admits the port, or is detached or edited later."],
                impact,
                "Bind published ports to 127.0.0.1 or the private/VPN address (for example `127.0.0.1:8080:8080`), or add DOCKER-USER rules; keep the Cloud Firewall rule as a second layer.",
                ["https://docs.docker.com/engine/network/packet-filtering-firewalls/"],
                ",".join(map(str, ports)),
            )
        )
    return output


def sshd_configuration(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    """HETZ-SSH-001 password login, HETZ-SSH-002 root password login, HETZ-SSH-003 empty passwords."""
    output: list[Finding] = []
    for server in _hosts(snapshot):
        sshd = server.properties.get("sshd")
        if not isinstance(sshd, dict) or not sshd:
            continue
        ports = [int(port) for port in sshd.get("port", ["22"]) if str(port).isdigit()] or [22]
        public = any(port in _cloud_world(server, snapshot, "tcp") for port in ports)
        password = sshd.get("passwordauthentication") == "yes" or sshd.get("kbdinteractiveauthentication") == "yes"
        checks = [
            (
                "HETZ-SSH-003", sshd.get("permitemptypasswords") == "yes", Severity.CRITICAL,
                "sshd accepts accounts with empty passwords", "permitemptypasswords yes",
                "Set PermitEmptyPasswords no.",
            ),
            (
                "HETZ-SSH-002", sshd.get("permitrootlogin") == "yes" and password, Severity.HIGH if public else Severity.MEDIUM,
                "sshd allows root to log in with a password", "permitrootlogin yes",
                "Set PermitRootLogin prohibit-password (or no) and log in as a named user.",
            ),
            (
                "HETZ-SSH-001",
                password,
                Severity.HIGH if public else Severity.LOW,
                "sshd accepts password logins" + (" on an Internet-reachable port" if public else ""),
                f"passwordauthentication {sshd.get('passwordauthentication')}, kbdinteractiveauthentication {sshd.get('kbdinteractiveauthentication')}",
                "Set PasswordAuthentication no and KbdInteractiveAuthentication no; use keys (ed25519) only.",
            ),
        ]
        for rule_id, unsafe, severity, title, actual, fix in checks:
            if not unsafe:
                continue
            output.append(
                _candidate(
                    rule_id, title, severity, 0.95, [server.id],
                    "The effective sshd configuration (sshd -T) enables a password-based login path.",
                    "SSH accepts public-key authentication only.",
                    actual,
                    [_evidence(server, "sshd_effective_config", {key: sshd.get(key) for key in ("permitrootlogin", "passwordauthentication", "kbdinteractiveauthentication", "permitemptypasswords", "port")}, "properties.sshd")],
                    ["internet" if public else "network peer", f"tcp/{ports[0]}", server.id],
                    ["A network path reaches sshd."],
                    "Password guessing or credential stuffing can yield a shell.",
                    fix,
                    ["https://man.openbsd.org/sshd_config"],
                )
            )
    return output


def host_firewall_absent(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    """HETZ-HOST-001: no active host firewall on a server with a public IP."""
    output: list[Finding] = []
    for server in _hosts(snapshot):
        props = server.properties
        firewall = props.get("host_firewall") or {}
        # Only a known engine that filters nothing counts; missing firewall evidence is a gap, not a finding.
        if firewall.get("engine") in (None, "unknown") or not firewall.get("known", True) or firewall.get("active") or not props.get("public_ip", True):
            continue
        cloud = bool(props.get("firewall_attached"))
        output.append(
            _candidate(
                "HETZ-HOST-001",
                "No host firewall is active" + ("; the Cloud Firewall is the only layer" if cloud else " and no Cloud Firewall is attached"),
                Severity.LOW if cloud else Severity.HIGH,
                0.9,
                [server.id],
                f"Host firewall engine {firewall.get('engine')} admits every port from the Internet (inactive, or policy accept without rules).",
                "A host firewall denies inbound traffic by default as a second layer behind the Cloud Firewall.",
                f"host firewall engine: {firewall.get('engine')}, admits: {firewall.get('world_tcp')}; Cloud Firewall attached: {cloud}.",
                [_evidence(server, "host_firewall_decision", firewall, "properties.host_firewall")],
                ["internet", server.id],
                ["The Cloud Firewall is detached, edited, or bypassed via another interface."],
                "A single Cloud Firewall change exposes every listener on the host.",
                "Enable UFW with default deny incoming and allow only the ports the host serves.",
                ["https://docs.hetzner.com/cloud/firewalls/overview/"],
            )
        )
    return output


def wide_data_binds(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    """HETZ-HOST-002: a data or control-plane service listens on all interfaces or a public address."""
    output: list[Finding] = []
    for server in _hosts(snapshot):
        listeners = server.properties.get("listeners") or []
        wide = sorted(
            {
                (item["port"], DATA_PORTS[item["port"]], item.get("process") or "?")
                for item in listeners
                if item.get("protocol") == "tcp" and item.get("bind") in {"wildcard", "public"} and item.get("port") in DATA_PORTS
            }
        )
        if not wide:
            continue
        reachable = [port for port, _, _ in wide if port in _cloud_world(server, snapshot, "tcp") and port in port_set(server.properties.get("host_firewall_allow_ports"))]
        output.append(
            _candidate(
                "HETZ-HOST-002",
                "Data or control-plane services listen on all interfaces",
                Severity.HIGH if reachable else Severity.LOW,
                0.9,
                [server.id],
                f"Listeners {[f'{name} ({port})' for port, name, _ in wide]} bind to 0.0.0.0/[::] or a public address.",
                "Data services bind to loopback or the private network address only.",
                f"Wide binds: {[port for port, _, _ in wide]}; reachable through both firewalls: {reachable or 'none'}.",
                [_evidence(server, "listening_socket", [{"port": port, "service": name, "process": process} for port, name, process in wide], "properties.listeners")],
                ["network peer", *(f"tcp/{port}" for port, _, _ in wide[:3]), server.id],
                ["A firewall layer admits the port."],
                "Only firewall rules separate the service from any network the host is attached to.",
                "Bind the service to 127.0.0.1 or the private network address (listen_addresses, bind, bind_ip).",
                ["https://www.postgresql.org/docs/current/runtime-config-connection.html"],
                ",".join(str(port) for port, _, _ in wide),
            )
        )
    return output


def container_isolation(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    """HETZ-DKR-006: dangerous capabilities or sensitive host mounts."""
    output: list[Finding] = []
    for container in snapshot.assets:
        if container.type != "container":
            continue
        caps = container.properties.get("dangerous_caps") or []
        mounts = container.properties.get("sensitive_mounts") or []
        if not caps and not mounts:
            continue
        output.append(
            _candidate(
                "HETZ-DKR-006",
                "Container holds dangerous capabilities or mounts sensitive host paths",
                Severity.HIGH,
                0.92,
                [container.id],
                f"Capabilities {caps or 'none'}; host mounts {mounts or 'none'}.",
                "Containers run with default capabilities and without host system paths.",
                f"cap_add={caps}, mounts={mounts}",
                [_evidence(container, "container_runtime", {"dangerous_caps": caps, "sensitive_mounts": mounts}, "properties")],
                [container.id, "host"],
                ["Code execution in the container."],
                "A compromised container can read or change the host.",
                "Drop the capabilities and replace host mounts with named volumes or narrower paths.",
                ["https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities"],
                ",".join([*caps, *mounts]),
            )
        )
    return output


def postgres_remote_auth(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    """HETZ-PG-003: the first pg_hba line a remote client selects allows a password without TLS."""
    output: list[Finding] = []
    for pg in snapshot.assets:
        if pg.type != "postgres":
            continue
        weak = [
            entry for entry in pg_remote_decisions(pg.properties.get("pg_hba") or [])
            if entry.get("method") in {"password", "md5", "scram-sha-256"} and entry.get("type") in {"host", "hostnossl"}
        ]
        if not weak:
            continue
        output.append(
            _candidate(
                "HETZ-PG-003",
                "Remote PostgreSQL clients can authenticate without TLS",
                Severity.MEDIUM,
                0.9,
                [pg.id],
                "pg_hba.conf lets a client from any address authenticate over host (TLS optional) or hostnossl.",
                "Remote rules use hostssl with scram-sha-256 or certificates, scoped to known client networks.",
                f"First-match lines: {[(entry.get('line'), entry.get('type'), entry.get('address'), entry.get('method')) for entry in weak]}.",
                [_evidence(pg, "pg_hba_rule", weak, "properties.pg_hba")],
                ["internet", pg.id, "postgres authentication"],
                ["A network path reaches PostgreSQL."],
                "Credentials and data can cross the network in clear text; password guessing reaches the server.",
                "Use hostssl lines with scram-sha-256 and scope the address to the private network.",
                ["https://www.postgresql.org/docs/current/auth-pg-hba-conf.html"],
            )
        )
    return output


HOST_RULES = (
    docker_firewall_bypass,
    sshd_configuration,
    host_firewall_absent,
    wide_data_binds,
    container_isolation,
    postgres_remote_auth,
)
