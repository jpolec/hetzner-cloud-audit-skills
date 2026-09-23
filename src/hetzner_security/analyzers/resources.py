"""Rules for resources beyond servers and firewalls: Storage Boxes, images, load balancers,
certificates, DNS records, and placement.

Every rule reads explicit provider state from the Hetzner API. Load balancer, certificate, and
DNS rules are covered by fixture tests (positive case plus clean twin).
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any

from ..graph import AttackGraph
from ..models import Asset, Finding, Severity, Snapshot
from .rules import _candidate, _evidence

# End of standard support (Ubuntu) or of LTS (Debian); source: vendor lifecycle pages.
# Dates are conservative (never earlier than the vendor's); re-check and bump OS_END_OF_SUPPORT_AS_OF.
OS_END_OF_SUPPORT_AS_OF = "2026-09-23"
OS_END_OF_SUPPORT = {
    ("ubuntu", "16.04"): "2021-04-30",
    ("ubuntu", "18.04"): "2023-05-31",
    ("ubuntu", "20.04"): "2025-05-31",
    ("ubuntu", "22.04"): "2027-06-01",
    ("ubuntu", "24.04"): "2029-05-31",
    ("debian", "9"): "2022-06-30",
    ("debian", "10"): "2024-06-30",
    ("debian", "11"): "2026-08-31",
    ("debian", "12"): "2028-06-30",
    ("centos", "7"): "2024-06-30",
    ("centos", "stream-8"): "2024-05-31",
    ("centos", "stream-9"): "2027-05-31",
    ("rocky", "8"): "2029-05-31",
    ("rocky", "9"): "2032-05-31",
    ("alma", "8"): "2029-03-01",
    ("alma", "9"): "2032-05-31",
    ("fedora", "39"): "2024-11-26",
    ("fedora", "40"): "2025-05-13",
}
INTERNAL_RANGES = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
)
CERT_WARN_DAYS = 30
CERT_CRITICAL_DAYS = 14


def _now(snapshot: Snapshot) -> datetime:
    collected = snapshot.metadata.get("collected_at")
    if isinstance(collected, str):
        try:
            return datetime.fromisoformat(collected.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(UTC)


def _date(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _of(snapshot: Snapshot, kind: str) -> list[Asset]:
    return [asset for asset in snapshot.assets if asset.type == kind]


def storage_box_exposure(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    output: list[Finding] = []
    for box in _of(snapshot, "storage_box"):
        access = box.properties.get("access_settings") or {}
        protocols = [name for name in ("ssh", "samba", "webdav", "zfs") if access.get(f"{name}_enabled")]
        if access.get("reachable_externally") and protocols:
            output.append(
                _candidate(
                    "HETZ-STO-001",
                    "Storage Box is reachable from outside Hetzner",
                    Severity.MEDIUM,
                    0.95,
                    [box.id],
                    f"{box.name} accepts {', '.join(protocols).upper()} from outside the Hetzner network.",
                    "Backup targets accept connections only from the servers that write to them.",
                    "access_settings.reachable_externally=true",
                    [_evidence(box, "storage_box_access", access, "properties.access_settings")],
                    ["internet", ", ".join(protocols), box.id],
                    [],
                    "Backup credentials leaked anywhere on the Internet give direct access to every stored backup.",
                    "Disable external reachability if only Hetzner servers write backups; otherwise restrict protocols and use SSH keys, not passwords.",
                    ["https://docs.hetzner.com/storage/storage-box/general"],
                )
            )
        if box.properties.get("snapshot_plan") in (None, {}):
            output.append(
                _candidate(
                    "HETZ-STO-002",
                    "Storage Box has no automatic snapshot plan",
                    Severity.MEDIUM,
                    0.95,
                    [box.id],
                    f"{box.name} has no snapshot plan, so backups can be overwritten or deleted with no point-in-time copy.",
                    "Backup storage keeps automatic snapshots that the writing server cannot delete.",
                    "snapshot_plan is not set",
                    [_evidence(box, "storage_box_snapshot_plan", None, "properties.snapshot_plan")],
                    ["compromised backup writer", "delete or encrypt backups", box.id],
                    [],
                    "Ransomware or a mistake on a server that writes backups can destroy the backups too.",
                    "Enable an automatic snapshot plan on the Storage Box and keep at least a week of snapshots.",
                    ["https://docs.hetzner.com/storage/storage-box/snapshots/"],
                )
            )
    return output


def operating_system_lifecycle(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    now = _now(snapshot)
    by_release: dict[tuple[str, str, str], list[Asset]] = {}
    for server in _of(snapshot, "server"):
        image = server.properties.get("image")
        if not isinstance(image, dict):
            continue
        key = (str(image.get("os_flavor", "")).lower(), str(image.get("os_version", "")).lower())
        end = OS_END_OF_SUPPORT.get(key)
        if end and datetime.fromisoformat(end).replace(tzinfo=UTC) < now:
            by_release.setdefault((key[0], key[1], end), []).append(server)
    return [
        _candidate(
            "HETZ-IMG-001",
            "Servers run an operating system past its end of support",
            Severity.MEDIUM,
            0.9,
            [server.id for server in servers],
            f"{len(servers)} server(s) were created from {flavor} {version}, whose standard support ended on {end}.",
            "Servers run a release that still receives security updates.",
            f"image {flavor} {version}; support ended {end}",
            [_evidence(server, "server_image", server.properties.get("image", {}).get("name"), "properties.image") for server in servers],
            ["unpatched OS", "known vulnerabilities", "server compromise"],
            ["The OS was not upgraded in place after creation (the API reports the creation image)."],
            "No security updates means known, public vulnerabilities stay open.",
            "Upgrade in place or rebuild on a supported release; check the running release with the host evidence bundle.",
            ["https://ubuntu.com/about/release-cycle", "https://wiki.debian.org/LTS"],
            f"{flavor}-{version}",
        )
        for (flavor, version, end), servers in by_release.items()
    ]


def load_balancer_hygiene(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    output: list[Finding] = []
    for lb in _of(snapshot, "load_balancer"):
        props = lb.properties
        services: list[dict[str, Any]] = props.get("services") or []
        targets: list[dict[str, Any]] = props.get("targets") or []
        public = bool((props.get("public_net") or {}).get("enabled", True))
        if not services or not targets:
            output.append(
                _candidate(
                    "HETZ-LB-001",
                    "Load balancer has no services or no targets",
                    Severity.LOW,
                    0.95,
                    [lb.id],
                    f"{lb.name} has {len(services)} service(s) and {len(targets)} target(s).",
                    "Every load balancer routes traffic to at least one target.",
                    "empty services or targets",
                    [_evidence(lb, "load_balancer_config", {"services": len(services), "targets": len(targets)}, "properties")],
                    [lb.id],
                    [],
                    "An idle load balancer is billed every month and often signals a half-finished migration.",
                    "Attach targets and services, or delete the load balancer through IaC.",
                    ["https://docs.hetzner.com/cloud/load-balancers/overview/"],
                )
            )
            continue
        protocols = {str(service.get("protocol")) for service in services}
        plain_http = [service for service in services if service.get("protocol") == "http"]
        redirected = any((service.get("http") or {}).get("redirect_http") for service in services if service.get("protocol") == "https")
        if public and plain_http and "https" not in protocols:
            output.append(
                _candidate(
                    "HETZ-LB-002",
                    "Public load balancer serves plain HTTP only",
                    Severity.MEDIUM,
                    0.95,
                    [lb.id],
                    f"{lb.name} listens on HTTP port(s) {sorted(int(s.get('listen_port', 0)) for s in plain_http)} and has no HTTPS service.",
                    "Public web traffic is served over HTTPS.",
                    "http services without an https service",
                    [_evidence(lb, "load_balancer_services", services, "properties.services")],
                    ["internet", "http", lb.id],
                    [],
                    "Credentials and session cookies cross the Internet unencrypted.",
                    "Add an HTTPS service with a managed certificate and enable redirect_http.",
                    ["https://docs.hetzner.com/cloud/load-balancers/getting-started/configure-https-with-a-managed-certificate/"],
                )
            )
        elif public and plain_http and not redirected:
            output.append(
                _candidate(
                    "HETZ-LB-003",
                    "Load balancer serves HTTP without redirecting to HTTPS",
                    Severity.LOW,
                    0.9,
                    [lb.id],
                    f"{lb.name} has both HTTP and HTTPS services, but HTTP is not redirected.",
                    "HTTP requests are redirected to HTTPS.",
                    "redirect_http is not enabled",
                    [_evidence(lb, "load_balancer_services", services, "properties.services")],
                    ["internet", "http", lb.id],
                    [],
                    "Clients that start on HTTP stay on an unencrypted connection.",
                    "Enable redirect_http on the HTTPS service.",
                    ["https://docs.hetzner.com/cloud/load-balancers/overview/"],
                )
            )
        unhealthy = [
            {"target": target.get("server", {}).get("id") or target.get("type"), "port": status.get("listen_port")}
            for target in targets
            for status in (target.get("health_status") or [])
            if status.get("status") == "unhealthy"
        ]
        if unhealthy:
            output.append(
                _candidate(
                    "HETZ-LB-004",
                    "Load balancer reports unhealthy targets",
                    Severity.MEDIUM,
                    0.9,
                    [lb.id],
                    f"{lb.name} reports {len(unhealthy)} unhealthy target check(s).",
                    "All load-balancer targets pass their health checks.",
                    f"unhealthy: {unhealthy[:5]}",
                    [_evidence(lb, "load_balancer_health", unhealthy, "properties.targets[].health_status")],
                    [lb.id],
                    [],
                    "Capacity is reduced; if every target fails, the service is down.",
                    "Check the failing targets and the health-check port and path.",
                    ["https://docs.hetzner.com/cloud/load-balancers/overview/"],
                )
            )
        server_targets = [target for target in targets if target.get("type") == "server"]
        if len(server_targets) == 1 and not any(target.get("type") == "label_selector" for target in targets):
            output.append(
                _candidate(
                    "HETZ-LB-005",
                    "Load balancer has a single target",
                    Severity.LOW,
                    0.9,
                    [lb.id],
                    f"{lb.name} forwards to one server, so the load balancer adds cost but no redundancy.",
                    "A load balancer spreads traffic across at least two targets.",
                    "one server target",
                    [_evidence(lb, "load_balancer_targets", targets, "properties.targets")],
                    [lb.id],
                    [],
                    "The single server is still a single point of failure.",
                    "Add a second target (ideally in a spread placement group), or remove the load balancer if redundancy is not needed.",
                    ["https://docs.hetzner.com/cloud/load-balancers/overview/"],
                )
            )
    return output


def load_balancer_bypass(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    """A load-balancer target that also accepts the target port from the whole Internet."""
    output: list[Finding] = []
    servers = {asset.id: asset for asset in _of(snapshot, "server")}
    for lb in _of(snapshot, "load_balancer"):
        for edge in graph.outgoing.get(lb.id, []):
            server = servers.get(edge.target)
            if server is None or edge.port is None:
                continue
            direct = [
                rule
                for rule in server.properties.get("inbound", []) or []
                if rule.get("protocol", "tcp") == "tcp"
                and set(rule.get("sources", []) or []) & {"0.0.0.0/0", "::/0"}
                and (rule.get("port_from") is None or int(rule.get("port_from")) <= edge.port <= int(rule.get("port_to") or rule.get("port_from")))
            ]
            if not direct:
                continue
            output.append(
                _candidate(
                    "HETZ-LB-006",
                    "Load-balancer backend is reachable directly, bypassing the load balancer",
                    Severity.MEDIUM,
                    0.8,
                    [server.id, lb.id],
                    f"{server.name} receives tcp/{edge.port} from {lb.name} and also accepts tcp/{edge.port} from any address.",
                    "Backends accept application traffic only from the load balancer (preferably over the private network).",
                    f"world rule on tcp/{edge.port}",
                    [_evidence(server, "firewall_rule", rule, "properties.inbound") for rule in direct]
                    + [_evidence(lb, "load_balancer_target", edge.port, "properties.targets")],
                    ["internet", f"tcp/{edge.port}", server.id],
                    ["The backend is meant to be reached only through the load balancer."],
                    "Direct requests skip TLS termination, health-based routing, and any protection in front of the load balancer.",
                    "Target the backend over its private IP and remove the public rule for the target port.",
                    ["https://docs.hetzner.com/cloud/load-balancers/overview/"],
                    f"{lb.id}:{edge.port}",
                )
            )
    return output


def certificate_lifecycle(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    output: list[Finding] = []
    now = _now(snapshot)
    for cert in _of(snapshot, "certificate"):
        props = cert.properties
        expires = _date(props.get("not_valid_after"))
        status = props.get("status") or {}
        failed = status.get("issuance") == "failed" or status.get("renewal") == "failed"
        if expires is not None or failed:
            days = (expires - now).days if expires else None
            if failed or (days is not None and days < CERT_WARN_DAYS):
                severity = Severity.HIGH if failed or (days is not None and days < CERT_CRITICAL_DAYS) else Severity.MEDIUM
                state = "renewal or issuance failed" if failed else ("expired" if days is not None and days < 0 else f"expires in {days} day(s)")
                output.append(
                    _candidate(
                        "HETZ-CERT-001",
                        "Certificate is expired, expiring soon, or failing to renew",
                        severity,
                        0.97,
                        [cert.id],
                        f"{cert.name} ({', '.join(props.get('domain_names') or [])}) {state}.",
                        f"Certificates renew automatically and stay valid for more than {CERT_WARN_DAYS} days.",
                        f"not_valid_after={props.get('not_valid_after')}; status={status}",
                        [_evidence(cert, "certificate_validity", {"not_valid_after": props.get("not_valid_after"), "status": status}, "properties")],
                        ["expired certificate", "TLS errors", cert.id],
                        [],
                        "Clients reject the site or API once the certificate expires.",
                        "Fix DNS validation for managed certificates, or upload a renewed certificate and switch the services to it.",
                        ["https://docs.hetzner.com/cloud/load-balancers/faq/"],
                    )
                )
        if props.get("used_by") == []:
            output.append(
                _candidate(
                    "HETZ-CERT-002",
                    "Certificate is not used by any load balancer",
                    Severity.LOW,
                    0.9,
                    [cert.id],
                    f"{cert.name} is attached to no service.",
                    "Unused certificates, and their private keys, are removed.",
                    "used_by is empty",
                    [_evidence(cert, "certificate_usage", [], "properties.used_by")],
                    [cert.id],
                    [],
                    "Leftover uploaded certificates keep private keys stored for no purpose.",
                    "Delete the certificate if nothing will use it.",
                    ["https://docs.hetzner.com/cloud/load-balancers/overview/"],
                )
            )
    return output


def _project_ips(
    snapshot: Snapshot,
) -> tuple[set[ipaddress.IPv4Address | ipaddress.IPv6Address], list[ipaddress.IPv6Network]]:
    """Addresses and IPv6 prefixes held by servers, load balancers, and primary or floating IPs."""
    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    networks: list[ipaddress.IPv6Network] = []
    for asset in snapshot.assets:
        props = asset.properties
        public = props.get("public_net") or {}
        values = [(public.get(family) or {}).get("ip") for family in ("ipv4", "ipv6")]
        if asset.type in {"primary_ip", "floating_ip"}:
            values.append(props.get("ip"))
        for value in values:
            if not isinstance(value, str):
                continue
            try:
                if "/" in value:
                    network = ipaddress.ip_network(value, strict=False)
                    if isinstance(network, ipaddress.IPv6Network):
                        networks.append(network)
                else:
                    addresses.add(ipaddress.ip_address(value))
            except ValueError:
                continue
    return addresses, networks


def dangling_dns(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    """A/AAAA records that point at public IPs this project does not own (possible subdomain takeover)."""
    rrsets = _of(snapshot, "dns_rrset")
    if not rrsets:
        return []
    owned, owned_v6 = _project_ips(snapshot)
    output: list[Finding] = []
    for rrset in rrsets:
        props = rrset.properties
        if props.get("type") not in {"A", "AAAA"}:
            continue
        for record in props.get("records") or []:
            try:
                address = ipaddress.ip_address(str(record.get("value", "")).strip())
            except ValueError:
                continue
            if any(address.version == network.version and address in network for network in INTERNAL_RANGES):
                output.append(
                    _candidate(
                        "HETZ-DNS-002",
                        "Public DNS record points to a private address",
                        Severity.LOW,
                        0.9,
                        [rrset.id],
                        f"{rrset.name} resolves to private address {address}.",
                        "Public zones publish only public addresses.",
                        f"{props.get('type')} {address}",
                        [_evidence(rrset, "dns_record", record.get("value"), "properties.records")],
                        [rrset.id],
                        [],
                        "Internal addressing leaks to anyone who queries the zone.",
                        "Move internal names to a private zone or remove the record.",
                        ["https://docs.hetzner.com/networking/dns/"],
                        str(address),
                    )
                )
                continue
            in_project = address in owned or any(
                isinstance(address, ipaddress.IPv6Address) and address in network for network in owned_v6
            )
            if not in_project:
                output.append(
                    _candidate(
                        "HETZ-DNS-001",
                        "DNS record points to an IP this project does not own",
                        Severity.MEDIUM,
                        0.6,
                        [rrset.id],
                        f"{rrset.name} ({props.get('type')}) points to {address}, which no server, load balancer, or IP in this project holds.",
                        "Records in a project's zone point at addresses the owner controls.",
                        f"{address} is not assigned in this project",
                        [_evidence(rrset, "dns_record", record.get("value"), "properties.records")],
                        ["dangling record", "released IP reassigned to another customer", "subdomain takeover"],
                        ["The address was released back to the provider, not moved to another project or provider."],
                        "If the address was released, whoever receives it next can serve content under your domain.",
                        "Confirm where the address lives; delete or update the record if the resource is gone.",
                        ["https://docs.hetzner.com/networking/dns/"],
                        str(address),
                    )
                )
    return output


def placement_spread(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    """Production servers that share a role should not share a physical host."""
    groups: dict[tuple[str, str], list[Asset]] = {}
    for server in _of(snapshot, "server"):
        if server.labels.get("environment") not in {"prod", "production"} or not server.labels.get("role"):
            continue
        groups.setdefault((server.labels["role"], server.labels.get("project", "")), []).append(server)
    output: list[Finding] = []
    for (role, project), servers in groups.items():
        if len(servers) < 2:
            continue
        spread = [server for server in servers if (server.properties.get("placement_group") or {}).get("type") == "spread"]
        if len(spread) == len(servers):
            continue
        output.append(
            _candidate(
                "HETZ-PLC-001",
                "Redundant production servers are not in a spread placement group",
                Severity.LOW,
                0.85,
                [server.id for server in servers],
                f"{len(servers)} production server(s) with role '{role}' are not all in a spread placement group.",
                "Replicas of one role run on different physical hosts.",
                f"{len(servers) - len(spread)} of {len(servers)} not in a spread group",
                [_evidence(server, "placement_group", server.properties.get("placement_group"), "properties.placement_group") for server in servers],
                ["one host failure", "all replicas down"],
                [],
                "A single hardware failure can take down every replica at once.",
                "Create a spread placement group for the role and place the servers in it (requires a rebuild or migration).",
                ["https://docs.hetzner.com/cloud/placement-groups/overview/"],
                f"{role}:{project}",
            )
        )
    return output


RESOURCE_RULES = (
    storage_box_exposure,
    operating_system_lifecycle,
    load_balancer_hygiene,
    load_balancer_bypass,
    certificate_lifecycle,
    dangling_dns,
    placement_spread,
)
