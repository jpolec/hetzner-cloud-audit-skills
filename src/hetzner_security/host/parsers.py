"""Parsers for the sections of a host evidence bundle.

Each parser takes the raw text a read-only command printed and returns plain data. Firewall
parsers evaluate rules in order (first match wins), which is how UFW and nftables decide.
Anything the parser cannot interpret is reported as ``unparsed`` instead of guessed.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

from ..flows import INTERNAL, PortSet

MARKER = re.compile(r"^===HETZNER-AUDIT (\w+)===$")
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
ABSENT = {"not installed", "not found"}
# UFW application profiles that ship with common packages; others are reported as unparsed.
UFW_APPS = {
    "openssh": ("tcp", PortSet.of([(22, 22)])),
    "nginx full": ("tcp", PortSet.of([(80, 80), (443, 443)])),
    "nginx http": ("tcp", PortSet.of([(80, 80)])),
    "nginx https": ("tcp", PortSet.of([(443, 443)])),
    "apache full": ("tcp", PortSet.of([(80, 80), (443, 443)])),
    "apache": ("tcp", PortSet.of([(80, 80)])),
    "apache secure": ("tcp", PortSet.of([(443, 443)])),
    "www full": ("tcp", PortSet.of([(80, 80), (443, 443)])),
    "www": ("tcp", PortSet.of([(80, 80)])),
    "www secure": ("tcp", PortSet.of([(443, 443)])),
}


def split_sections(text: str) -> dict[str, str]:
    if len(text.encode()) > MAX_BUNDLE_BYTES:
        raise ValueError(f"host bundle exceeds {MAX_BUNDLE_BYTES} bytes")
    if not text.lstrip().startswith("hetzner-audit-host-bundle"):
        raise ValueError("not a hetzner-audit host bundle (missing header line)")
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        match = MARKER.match(line.strip())
        if match:
            current = match.group(1)
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    return {name: "\n".join(lines).strip() for name, lines in sections.items()}


def present(section: str | None) -> bool:
    return section is not None and bool(section.strip()) and section.strip() not in ABSENT


def parse_meta(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip().lower()] = value.strip().strip('"')
    return values


# --- Host firewall -------------------------------------------------------------------------
#
# Every engine (UFW, nftables, iptables) is normalized to ordered rules plus a default policy and
# evaluated by one first-match function. Anything the parser does not fully understand makes
# the answer None (unknown): an unknown host firewall never rejects or confirms a finding.

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
# Interfaces that never carry public or Hetzner private-network traffic.
TUNNEL_IFACES = ("lo", "tailscale", "wt", "wg", "docker", "br-", "veth", "cni", "flannel", "cilium", "lxc", "virbr", "zt", "kube")
# Hetzner Cloud uplinks: public NIC (eth0 / enp1s0) and private-network NIC (ens10 / enp7s0).
PUBLIC_IFACES = {"eth0", "enp1s0", "ens3", "eno1", "enp0s31f6"}
PRIVATE_IFACES = {"ens10", "enp7s0", "ens11", "enp8s0"}


def _network(value: str) -> Network | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def iface_scope(name: str | None, private: bool) -> str:
    """apply / skip / unknown for a rule bound to an interface, from the client's side."""
    if not name:
        return "apply"
    name = name.strip('"').rstrip("+*")
    if name.startswith(TUNNEL_IFACES):
        return "skip"
    if name in PUBLIC_IFACES:
        return "skip" if private else "apply"
    if name in PRIVATE_IFACES:
        return "apply" if private else "skip"
    return "unknown"


def _rule(action: str, protocol: str = "any", ports: PortSet | None = None, source: Network | None = None,
          family: int | None = None, iface: str | None = None, unsupported: bool = False) -> dict[str, Any]:
    return {"action": action, "protocol": protocol, "ports": ports if ports is not None else PortSet.full(),
            "source": source, "family": family, "iface": iface, "unsupported": unsupported}


def evaluate_chain(chain: dict[str, Any], protocol: str, client: str, private: bool = False) -> tuple[PortSet | None, bool]:
    """(ports admitted from ``client``, partial) with first-match semantics; None when unknown.

    ``partial`` is True when an accept rule admits only part of the client range (for example one
    peer inside the private network): the whole range is not admitted, but some sources are.
    """
    network = _network(client)
    if network is None or chain.get("error"):
        return None, False
    decided, allowed, partial = PortSet(), PortSet(), False
    for rule in chain.get("rules", []):
        if rule["unsupported"]:
            return None, partial
        if rule["family"] and rule["family"] != network.version:
            continue
        if rule["protocol"] not in ("any", protocol):
            continue
        source: Network | None = rule["source"]
        if source is not None:
            if source.version != network.version:
                continue
            if not network.subnet_of(source):  # type: ignore[arg-type]
                if source.overlaps(network) and rule["action"] == "accept":
                    partial = True
                continue
        scope = iface_scope(rule["iface"], private)
        if scope == "skip":
            continue
        if scope == "unknown":
            return None, partial
        fresh = rule["ports"].difference(decided)
        if rule["action"] == "accept":
            allowed = allowed.union(fresh)
        decided = decided.union(fresh)
    if chain.get("policy") == "accept":
        allowed = allowed.union(PortSet.full().difference(decided))
    return allowed, partial


def _ufw_ports(spec: str) -> tuple[str, PortSet] | None:
    """'22/tcp', '80,443/tcp', '6000:6007/udp', '22' (both protocols) -> (protocol, ports)."""
    port_part, _, protocol = spec.partition("/")
    spans = []
    for piece in port_part.split(","):
        first, _, last = piece.partition(":")
        if not first.isdigit() or (last and not last.isdigit()):
            return None
        spans.append((int(first), int(last or first)))
    return (protocol or "any"), PortSet.of(spans)


UFW_ROW = re.compile(r"^(?P<to>.+?)\s+(?P<action>ALLOW|DENY|REJECT|LIMIT)(?:\s+(?P<direction>IN|OUT|FWD))?\s+(?P<source>\S.*)$")


def parse_ufw(text: str) -> dict[str, Any]:
    """Parse ``ufw status verbose`` into ordered rules and the incoming default."""
    if not present(text):
        return {"engine": "ufw", "installed": False}
    if "need to be root" in text or "ERROR" in text:
        return {"engine": "ufw", "installed": True, "error": text.strip().splitlines()[0][:200]}
    status = re.search(r"^Status:\s*(\w+)", text, re.M)
    default = re.search(r"^Default:\s*(\w+)\s*\(incoming\)", text, re.M)
    rules: list[dict[str, Any]] = []
    unparsed: list[str] = []
    in_table = False
    for line in text.splitlines():
        if line.startswith("--"):
            in_table = True
            continue
        if not in_table or not line.strip():
            continue
        match = UFW_ROW.match(line.strip())
        if not match:
            unparsed.append(line.strip())
            continue
        if match.group("direction") in {"OUT", "FWD"}:
            continue  # outbound and routed rules do not govern inbound traffic to the host
        to, source = match.group("to"), match.group("source")
        v6 = "(v6)" in to or "(v6)" in source
        to = to.replace("(v6)", "").strip()
        source = re.sub(r"\(v6\)|\(out\)", "", source).strip()
        interface = None
        if " on " in to:
            to, _, interface = to.partition(" on ")
            to, interface = to.strip(), interface.strip()
        if to == "Anywhere":
            ports: tuple[str, PortSet] | None = ("any", PortSet.full())
        else:
            tokens = to.split()
            ports = _ufw_ports(tokens[-1]) if tokens else None
            ports = ports or UFW_APPS.get(to.lower())
        source_network = None if source.startswith("Anywhere") else _network(source.split()[0])
        if ports is None or (not source.startswith("Anywhere") and source_network is None):
            unparsed.append(line.strip())
            continue
        action = match.group("action").lower()
        rules.append(_rule("accept" if action in {"allow", "limit"} else "drop", ports[0], ports[1], source_network,
                           6 if v6 else 4, interface) | {"text": line.strip()})
    return {
        "engine": "ufw",
        "installed": True,
        "active": bool(status and status.group(1).lower() == "active"),
        "default_incoming": default.group(1).lower() if default else None,
        "policy": "accept" if default and default.group(1).lower() == "allow" else "drop",
        "rules": rules,
        "unparsed": unparsed,
    }


def ufw_allowed(parsed: dict[str, Any], protocol: str, client: str, private: bool = False) -> PortSet | None:
    """Ports UFW admits from ``client`` (a CIDR). None when the answer is not evidenced."""
    if not parsed.get("installed") or parsed.get("error") or "rules" not in parsed:
        return None
    if not parsed.get("active"):
        return PortSet.full()
    if parsed.get("unparsed"):
        return None  # a rule we cannot read might admit or deny anything
    return evaluate_chain(parsed, protocol, client, private)[0]


NFT_DPORT = re.compile(r"\b(tcp|udp|th)\s+dport\s+(!=\s*)?(\{[^}]*\}|\S+)")
NFT_KNOWN = re.compile(
    r"^(ip6?\s+saddr\s+\S+|ip6?\s+daddr\s+\S+|(tcp|udp|th)\s+dport\s+(\{[^}]*\}|\S+)|(tcp|udp)\s+sport\s+\S+|meta\s+l4proto\s+\S+|"
    r"ip\s+protocol\s+\S+|ip6\s+nexthdr\s+\S+|meta\s+nfproto\s+\S+|iif(name)?\s+\S+|ct\s+state\s+(\{[^}]*\}|\S+)|"
    r"icmp(v6)?\s+type\s+(\{[^}]*\}|\S+)|counter|log(\s+prefix\s+\"[^\"]*\")?|limit\s+rate\s+\S+(\s+\S+)?|"
    r"accept|drop|reject(\s+with\s+.*)?)\s*"
)


def _nft_ports(value: str) -> PortSet | None:
    spans = []
    for piece in value.strip("{} ").split(","):
        piece = piece.strip()
        if not piece:
            continue
        first, _, last = piece.partition("-")
        if not first.isdigit() or (last and not last.isdigit()):
            return None
        spans.append((int(first), int(last or first)))
    return PortSet.of(spans)


def _nft_rule(line: str) -> dict[str, Any] | None:
    """One nft rule as a normalized rule; None to ignore it (return traffic, no verdict)."""
    line = re.sub(r'\s*comment\s+"[^"]*"\s*$', "", line)
    line = re.sub(r"\bcounter packets \d+ bytes \d+", "counter", line).strip()
    if re.search(r"\b(jump|goto)\b", line):
        return _rule("drop", unsupported=True)
    verdicts = re.findall(r"\b(accept|drop|reject)\b", line)
    if not verdicts:
        return None  # counters or logging only
    states = re.search(r"\bct\s+state\s+(\{[^}]*\}|\S+)", line)
    if states and "new" not in states.group(1):
        return None  # established/related/invalid: never decides a new connection
    rest = line
    while rest:
        match = NFT_KNOWN.match(rest)
        if not match:
            return _rule("drop", unsupported=True)  # a match we do not model could restrict the rule
        rest = rest[match.end():]
    protocol = "any"
    dport = NFT_DPORT.search(line)
    if dport and dport.group(2):
        return _rule("drop", unsupported=True)  # negated port match
    ports = PortSet.full()
    if dport:
        parsed_ports = _nft_ports(dport.group(3))
        if parsed_ports is None:
            return _rule("drop", unsupported=True)
        ports, protocol = parsed_ports, ("any" if dport.group(1) == "th" else dport.group(1))
    l4 = re.search(r"\b(?:meta\s+l4proto|ip\s+protocol|ip6\s+nexthdr)\s+(\S+)", line)
    if l4:
        protocol = l4.group(1).strip("{}") if l4.group(1).strip("{}") in {"tcp", "udp"} else "other"
    if re.search(r"\bicmp(v6)?\s+type\b", line):
        protocol = "other"
    family = 6 if re.search(r"\bip6\s|meta\s+nfproto\s+ipv6", line) else 4 if re.search(r"\bip\s+(saddr|daddr|protocol)|meta\s+nfproto\s+ipv4", line) else None
    saddr = re.search(r"\bip6?\s+saddr\s+(\S+)", line)
    source = None
    if saddr:
        source = _network(saddr.group(1))
        if source is None:
            return _rule("drop", unsupported=True)  # named sets and ranges are not modeled
    iface = re.search(r"\biif(?:name)?\s+(\S+)", line)
    return _rule("accept" if verdicts[-1] == "accept" else "drop", protocol, ports, source, family,
                 iface.group(1).strip('"') if iface else None)


def parse_nftables(text: str) -> dict[str, Any]:
    """Parse input-hook chains of ``nft list ruleset``."""
    if not present(text):
        return {"engine": "nftables", "installed": text.strip() != "not installed"} if text.strip() else {"engine": "nftables", "installed": False}
    if re.search(r"Error:|Operation not permitted|Permission denied", text):
        return {"engine": "nftables", "installed": True, "error": text.strip().splitlines()[0][:200]}
    chains: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("chain "):
            current = {"name": line.split()[1], "hook": None, "policy": None, "rules": []}
            chains.append(current)
            continue
        if current is None or not line or line == "}":
            continue
        if line.startswith("type ") and "hook" in line:
            hook = re.search(r"hook\s+(\w+)", line)
            policy = re.search(r"policy\s+(\w+)", line)
            current["hook"] = hook.group(1) if hook else None
            current["policy"] = policy.group(1) if policy else "accept"
            continue
        rule = _nft_rule(line)
        if rule is not None:
            current["rules"].append(rule | {"text": line})
    return {"engine": "nftables", "installed": True, "input_chains": [chain for chain in chains if chain["hook"] == "input"]}


def nftables_allowed(parsed: dict[str, Any], protocol: str, client: str, private: bool = False) -> PortSet | None:
    chains = parsed.get("input_chains")
    if not parsed.get("installed") or parsed.get("error") or chains is None:
        return None
    if not chains:
        return PortSet.full()  # no input hook: nothing filters inbound traffic
    result: PortSet | None = None
    for chain in chains:
        allowed, _ = evaluate_chain(chain, protocol, client, private)
        if allowed is None:
            return None
        # Every input-hook chain must accept a packet for it to pass.
        result = allowed if result is None else result.intersection(allowed)
    return result


def parse_iptables(text: str) -> dict[str, Any]:
    """``iptables -S INPUT`` (or ip6tables): policy and rules, for hosts on iptables-legacy."""
    if not present(text):
        return {"installed": False}
    if re.search(r"Permission denied|can't initialize|not permitted|No chain", text):
        return {"installed": True, "error": text.strip().splitlines()[0][:200]}
    policy = "accept"
    rules: list[dict[str, Any]] = []
    for line in text.splitlines():
        tokens = line.split()
        if tokens[:2] == ["-P", "INPUT"] and len(tokens) > 2:
            policy = "accept" if tokens[2] == "ACCEPT" else "drop"
            continue
        if tokens[:2] != ["-A", "INPUT"]:
            continue
        options: dict[str, str] = {}
        index, unsupported = 2, False
        while index < len(tokens):
            word = tokens[index]
            if word == "!":
                unsupported = True
                index += 1
                continue
            value = tokens[index + 1] if index + 1 < len(tokens) else ""
            if word in {"-p", "-s", "-i", "-j", "--dport", "--dports", "--ctstate", "--state", "-m", "--comment"}:
                options[word] = value
                index += 2
            else:
                unsupported = unsupported or word not in {"--tcp-flags", "--syn"}
                index += 1
        target = options.get("-j", "")
        states = options.get("--ctstate") or options.get("--state")
        if states and "NEW" not in states:
            continue
        if target not in {"ACCEPT", "DROP", "REJECT"}:
            rules.append(_rule("drop", unsupported=True) | {"text": line})  # RETURN, LOG, or a user chain
            continue
        ports = PortSet.full()
        spec = options.get("--dport") or options.get("--dports")
        if spec:
            spans = []
            for piece in spec.split(","):
                first, _, last = piece.partition(":")
                if not first.isdigit() or (last and not last.isdigit()):
                    unsupported = True
                    break
                spans.append((int(first), int(last or first)))
            ports = PortSet.of(spans)
        source = _network(options["-s"]) if "-s" in options else None
        protocol = options.get("-p", "any")
        rules.append(_rule("accept" if target == "ACCEPT" else "drop", protocol if protocol in {"tcp", "udp", "any"} else "other",
                           ports, source, None, options.get("-i"), unsupported or ("-s" in options and source is None)) | {"text": line})
    return {"installed": True, "policy": policy, "rules": rules}


def iptables_allowed(parsed: dict[str, Any], protocol: str, client: str, private: bool = False) -> PortSet | None:
    if not parsed.get("installed") or parsed.get("error") or "rules" not in parsed:
        return None
    return evaluate_chain(parsed, protocol, client, private)[0]


def iptables_filters(parsed: dict[str, Any]) -> bool:
    return bool(parsed.get("rules")) or parsed.get("policy") == "drop"


def parse_docker_user(text: str) -> dict[str, Any]:
    """``iptables -S DOCKER-USER``: any rule beyond RETURN filters published container ports."""
    if not present(text):
        return {"installed": False}
    if re.search(r"Permission denied|can't initialize|not permitted", text):
        return {"installed": True, "filters": None, "error": text.strip().splitlines()[0][:200]}
    if "No chain" in text or "does not exist" in text:
        return {"installed": True, "filters": False}
    rules = [line for line in text.splitlines() if line.startswith("-A DOCKER-USER")]
    filtering = [line for line in rules if not line.rstrip().endswith("-j RETURN")]
    return {"installed": True, "filters": bool(filtering), "rules": len(filtering)}


# --- Listeners -----------------------------------------------------------------------------


def bind_class(address: str) -> str:
    """wildcard, loopback, internal (RFC 1918, CGNAT/Tailscale, ULA), or public."""
    address = address.strip("[]").split("%")[0]
    if address in {"*", "0.0.0.0", "::", ""}:
        return "wildcard"
    if address.startswith("::ffff:"):
        address = address.removeprefix("::ffff:")
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "unknown"
    if ip.is_loopback:
        return "loopback"
    if any(ip.version == network.version and ip in network for network in INTERNAL):
        return "internal"
    return "public"


SS_PROCESS = re.compile(r'users:\(\("([^"]+)"')
# 0.0.0.0:22, [::]:22, *:22, 127.0.0.53%lo:53, [fe80::1]%eth0:546, [::ffff:10.0.0.2]:80
SS_LOCAL = re.compile(r"^(?P<addr>\[[^\]]*\]|[^%\[\]]*?)(?:%(?P<iface>[^:\]]+))?:(?P<port>\d+)$")


def parse_listeners(text: str) -> dict[str, Any]:
    """``ss -H -ltunp``: one listener per line (Netid State Recv-Q Send-Q Local Peer Process)."""
    if not present(text):
        return {"installed": False}
    listeners = []
    unparsed = []
    for line in text.splitlines():
        columns = line.split()
        if len(columns) < 5 or columns[0] not in {"tcp", "udp"}:
            if line.strip():
                unparsed.append(line.strip())
            continue
        local = SS_LOCAL.match(columns[4])
        if not local:
            unparsed.append(line.strip())
            continue
        address, iface, port = local.group("addr").strip("[]"), local.group("iface"), local.group("port")
        process = SS_PROCESS.search(line)
        bind = bind_class(address)
        if iface == "lo" or (iface and iface.startswith(("lo", "docker", "br-", "veth"))):
            bind = "loopback" if iface == "lo" else "internal"  # a wildcard bound to one local interface
        listeners.append(
            {
                "protocol": columns[0],
                "address": address,
                "iface": iface,
                "port": int(port),
                "bind": bind,
                "process": process.group(1) if process else None,
            }
        )
    return {"installed": True, "listeners": listeners, "unparsed": unparsed}


# --- sshd, Docker, PostgreSQL, Redis -------------------------------------------------------


def parse_sshd(text: str) -> dict[str, Any]:
    if not present(text):
        return {}
    config: dict[str, Any] = {}
    for line in text.splitlines():
        key, _, value = line.strip().partition(" ")
        if key:
            key = key.lower()
            config[key] = [*config.get(key, []), value.strip()] if key == "port" else value.strip().lower()
    return config


SENSITIVE_MOUNTS = ("/", "/etc", "/root", "/home", "/proc", "/sys", "/boot", "/var/lib/docker", "/dev")
DOCKER_SOCKETS = ("/var/run/docker.sock", "/run/docker.sock")
DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN", "DAC_READ_SEARCH", "SYS_RAWIO"}


def parse_docker(text: str) -> dict[str, Any]:
    if not present(text):
        return {"installed": text.strip() != "not installed", "containers": []}
    if any(line.startswith("error:") for line in text.splitlines()):
        return {"installed": True, "error": text.strip().splitlines()[0][:200], "containers": []}
    containers = []
    unparsed = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            if line:
                unparsed.append(line[:200])
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            unparsed.append(line[:200])
            continue
        published = []
        for spec, bindings in (raw.get("ports") or {}).items():
            container_port, _, protocol = spec.partition("/")
            for binding in bindings or []:
                host_port = str(binding.get("HostPort", ""))
                if not host_port.isdigit():
                    continue
                host_ip = binding.get("HostIp") or "0.0.0.0"
                published.append(
                    {
                        "host_ip": host_ip,
                        "bind": bind_class(host_ip),
                        "host_port": int(host_port),
                        "container_port": int(container_port) if container_port.isdigit() else None,
                        "protocol": protocol or "tcp",
                    }
                )
        mounts = [
            {"source": mount.get("Source"), "destination": mount.get("Destination"), "rw": mount.get("RW", True)}
            for mount in raw.get("mounts") or []
            if isinstance(mount, dict)
        ]
        caps = sorted({str(cap).upper().removeprefix("CAP_") for cap in raw.get("cap_add") or []})
        containers.append(
            {
                "name": str(raw.get("name", "")).lstrip("/"),
                "image": raw.get("image"),
                "user": raw.get("user") or "",
                "privileged": bool(raw.get("privileged")),
                "host_pid": raw.get("pid_mode") == "host",
                "host_network": raw.get("network_mode") == "host",
                "docker_socket": any(mount["source"] in DOCKER_SOCKETS for mount in mounts),
                "sensitive_mounts": sorted(
                    {mount["source"] for mount in mounts if mount["source"] in SENSITIVE_MOUNTS}
                ),
                "cap_add": caps,
                "dangerous_caps": sorted(set(caps) & DANGEROUS_CAPS),
                "security_opt": raw.get("security_opt") or [],
                "published": published,
            }
        )
    return {"installed": True, "containers": containers, "unparsed": unparsed}


def parse_pg_hba(text: str) -> dict[str, Any]:
    """pg_hba.conf entries in file order; order matters because the first matching line decides."""
    if not present(text):
        return {"found": False, "files": {}}
    files: dict[str, list[dict[str, Any]]] = {}
    current = "pg_hba.conf"
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("# file "):
            current = line.removeprefix("# file ").strip()
            files[current] = []
            continue
        if not line or line.startswith("#"):
            continue
        columns = line.split()
        kind = columns[0]
        entry: dict[str, Any]
        if kind == "local" and len(columns) >= 4:
            entry = {"type": kind, "database": columns[1], "user": columns[2], "address": None, "method": columns[3]}
        elif kind.startswith("host") and len(columns) >= 5:
            address, method_index = columns[3], 4
            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", columns[4]) and len(columns) >= 6:
                network = _network(f"{columns[3]}/{columns[4]}")  # address + netmask form
                address, method_index = (str(network) if network else columns[3]), 5
            entry = {"type": kind, "database": columns[1], "user": columns[2], "address": address, "method": columns[method_index]}
        else:
            continue  # include directives and malformed lines are not evaluated
        entry["line"] = len(files.setdefault(current, [])) + 1
        files[current].append(entry)
    return {"found": bool(files), "files": files}


def pg_address_matches_world(address: str | None) -> bool:
    if address in {"all", "0.0.0.0/0", "::/0", "0.0.0.0/0.0.0.0"}:
        return True
    network = _network(address or "")
    if network is None:
        return False
    return network.prefixlen <= (8 if network.version == 4 else 16) and not any(
        network.version == internal.version and network.subnet_of(internal)  # type: ignore[arg-type]
        for internal in INTERNAL
    )


TYPE_COVERS = {"host": {"host", "hostssl", "hostnossl", "hostgssenc", "hostnogssenc"},
               "hostssl": {"hostssl"}, "hostnossl": {"hostnossl"}, "hostgssenc": {"hostgssenc"}, "hostnogssenc": {"hostnogssenc"}}


def _pg_family(address: str | None) -> set[int]:
    if address in {None, "all", "samehost", "samenet"}:
        return {4, 6}
    network = _network(address or "")
    return {network.version} if network else {4, 6}


def _pg_covers(reject: dict[str, Any], entry: dict[str, Any]) -> bool:
    """True when a reject line matches every connection ``entry`` would match."""
    if str(entry.get("type", "host")) not in TYPE_COVERS.get(str(reject.get("type", "host")), set()):
        return False
    if not _pg_family(entry.get("address")) <= _pg_family(reject.get("address")):
        return False
    for key in ("database", "user"):
        if reject.get(key) != "all" and reject.get(key) != entry.get(key):
            return False
    if reject.get("address") in {"all", None}:
        return True
    outer, inner = _network(str(reject.get("address"))), _network(str(entry.get("address")))
    return bool(outer and inner and inner.version == outer.version and inner.subnet_of(outer))  # type: ignore[arg-type]


def pg_remote_decisions(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Entries a remote Internet client can actually select, in first-match order.

    A ``reject`` line hides a later line only when it covers it: same or broader connection type
    (host covers hostssl and hostnossl), the same address family, a superset address range, and
    the same or broader database and user. Anything else stays selectable.
    """
    rejects: list[dict[str, Any]] = []
    output = []
    for entry in entries:
        kind = str(entry.get("type", "host"))  # normalized fixtures may omit the type
        if not kind.startswith("host"):
            continue
        if entry.get("method") == "reject":
            rejects.append(entry)
            continue
        if not pg_address_matches_world(entry.get("address")):
            continue
        if any(_pg_covers(reject, entry) for reject in rejects):
            continue
        output.append(entry)
    return output


def parse_redis(text: str) -> dict[str, Any]:
    if not present(text):
        return {"installed": text.strip() != "not installed"}
    if "Could not connect" in text or "Connection refused" in text:
        return {"installed": True, "running": False}
    if "NOAUTH" in text:
        return {"installed": True, "running": True, "auth_required": True}
    if re.search(r"NOPERM|ERR unknown command|ERR unknown subcommand", text):
        return {"installed": True, "running": True, "error": "CONFIG not readable (renamed or not permitted)"}
    # CONFIG GET prints the key, then the value on the next line; an empty value is an empty line.
    lines = [line.strip() for line in text.splitlines()]
    values: dict[str, str] = {}
    for key, value in zip(lines, lines[1:], strict=False):
        if key in {"bind", "protected-mode", "requirepass"} and key not in values:
            values[key] = value
    lines = [line for line in lines if line]
    users = [line.split() for line in lines if line.startswith("user ")]
    default = next((user for user in users if len(user) > 1 and user[1] == "default"), None)
    default_open = bool(default and "on" in default and "nopass" in default)
    return {
        "installed": True,
        "running": True,
        "bind": values.get("bind", "").split(),
        "protected_mode": values.get("protected-mode", "yes") == "yes",
        "requirepass": values.get("requirepass") == "<set>",
        "acl_enabled": bool(users) and not default_open,
        "acl_users": len(users),
    }
