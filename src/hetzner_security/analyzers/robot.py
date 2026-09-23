"""Hetzner Robot rules (``--robot``): dedicated servers without a Robot firewall, sensitive ports
the Robot firewall admits, unfiltered IPv6, and vSwitch coupling to Cloud networks.

The Robot firewall evaluates input rules in order; the first match decides and anything
unmatched is discarded. It filters the public uplink only, never vSwitch VLAN traffic.
"""

from __future__ import annotations

from ..collectors.robot import robot_exposure
from ..flows import PortSet
from ..graph import AttackGraph
from ..models import Finding, Severity, Snapshot
from .rules import SENSITIVE_SERVICES, _candidate, _evidence

REFERENCE = ["https://docs.hetzner.com/robot/dedicated-server/firewall/"]
SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def robot_firewall(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    output: list[Finding] = []
    for server in snapshot.assets:
        if server.type != "robot_server" or server.properties.get("cancelled"):
            continue
        firewall = server.properties.get("robot_firewall") or {}
        if firewall.get("status") == "unknown":
            continue  # the Robot API refused the firewall read; coverage reports it
        if not firewall.get("present") or firewall.get("status") != "active":
            output.append(
                _candidate(
                    "HETZ-ROB-001",
                    "Dedicated server has no active Robot firewall",
                    Severity.HIGH,
                    0.8,
                    [server.id],
                    f"Robot firewall status: {firewall.get('status') or 'not configured'}.",
                    "Every dedicated server filters inbound traffic before it reaches the host.",
                    f"robot_firewall={firewall.get('status') or 'absent'}",
                    [_evidence(server, "robot_firewall", {"status": firewall.get("status"), "present": firewall.get("present")}, "properties.robot_firewall")],
                    ["internet", server.id],
                    ["No host firewall denies the traffic."],
                    "Every listener on the server's public address is reachable from the Internet.",
                    "Enable the Robot firewall with a default-discard template and explicit accepts.",
                    REFERENCE,
                )
            )
            continue
        world = robot_exposure(firewall, "tcp")
        world_udp = robot_exposure(firewall, "udp")
        exposed = [
            (first, last, f"{name}{' (UDP)' if proto == 'udp' else ''}", severity)
            for proto, first, last, name, severity in SENSITIVE_SERVICES
            if (world if proto == "tcp" else world_udp).intersection(PortSet.of([(first, last)]))
        ]
        if 22 in world:
            exposed.insert(0, (22, 22, "SSH", Severity.HIGH))
        if exposed:
            severity = max((item[3] for item in exposed), key=SEVERITY_ORDER.index)
            output.append(
                _candidate(
                    "HETZ-ROB-002",
                    "Robot firewall admits sensitive services from the Internet",
                    severity,
                    0.85,
                    [server.id],
                    f"First-match evaluation admits TCP {world.describe() or 'none'} and UDP {world_udp.describe() or 'none'} from any source.",
                    "Management and data ports accept only VPN, bastion, or explicit client ranges.",
                    "; ".join(f"{name} ({first}{'-' + str(last) if last != first else ''})" for first, last, name, _ in exposed[:6]),
                    [_evidence(server, "robot_firewall_rule", firewall.get("rules"), "properties.robot_firewall.rules")],
                    ["internet", *(f"tcp/{first}" for first, _, _, _ in exposed[:3]), server.id],
                    ["A service listens on the port and no host firewall denies it."],
                    "An unauthenticated peer can reach a management or data service.",
                    "Restrict the accept rules to known source ranges and put a discard rule for the rest first.",
                    REFERENCE,
                    world.describe(),
                )
            )
        if not firewall.get("filter_ipv6") and server.properties.get("server_ipv6_net"):
            output.append(
                _candidate(
                    "HETZ-ROB-005",
                    "Robot firewall does not filter IPv6",
                    Severity.MEDIUM,
                    0.9,
                    [server.id],
                    "The firewall is active for IPv4, but filter_ipv6 is off and the server has an IPv6 subnet.",
                    "IPv6 is filtered like IPv4, or disabled on the host.",
                    f"filter_ipv6=false; IPv6 net {server.properties.get('server_ipv6_net')}",
                    [_evidence(server, "robot_firewall", {"filter_ipv6": False}, "properties.robot_firewall.filter_ipv6")],
                    ["internet (IPv6)", server.id],
                    ["The host has a global IPv6 address and a listener on it."],
                    "Every IPv4 rule is bypassed over IPv6.",
                    "Enable 'Filter IPv6 packets' in the Robot firewall, or configure IPv6 rules on the host.",
                    REFERENCE,
                )
            )
    return output


def vswitch_coupling(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    output: list[Finding] = []
    for vswitch in snapshot.assets:
        if vswitch.type != "vswitch" or not vswitch.properties.get("cloud_network"):
            continue
        networks = [f"hcloud:network:{item.get('id')}" for item in vswitch.properties["cloud_network"]]
        members = [f"robot:server:{number}" for number in vswitch.properties.get("servers") or []]
        known = set(snapshot.asset_map())
        output.append(
            _candidate(
                "HETZ-ROB-003",
                "vSwitch joins dedicated servers and a Cloud network without any provider filter",
                Severity.LOW,
                0.9,
                [vswitch.id, *[item for item in [*networks, *members] if item in known]],
                f"{len(members)} dedicated server(s) share a flat network with Cloud network(s) {networks}.",
                "Hybrid links are filtered on the hosts, or limited to the servers that need them.",
                f"vlan {vswitch.properties.get('vlan')}; members {members}; cloud networks {networks}",
                [_evidence(vswitch, "vswitch_cloud_coupling", vswitch.properties["cloud_network"], "properties.cloud_network")],
                [*members[:1], vswitch.id, *networks[:1]],
                ["A host on either side is compromised."],
                "Neither Cloud Firewalls nor the Robot firewall filter vSwitch traffic; a compromise on one side reaches every port on the other.",
                "Filter the private interfaces on each host (UFW/nftables) and keep only required servers in the vSwitch.",
                ["https://docs.hetzner.com/cloud/networks/connect-dedi-vswitch/"],
            )
        )
    return output


ROBOT_RULES = (robot_firewall, vswitch_coupling)
