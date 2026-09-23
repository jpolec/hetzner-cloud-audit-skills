"""Synthetic example projects for the README gallery. Every name, ID, and address is invented.

Usage: uv run python scripts/make_gallery.py OUTPUT_DIR, then render each JSON with
`hetzner-audit map --input OUTPUT_DIR/NAME.json --format svg --title ...` (see docs/assets/examples).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from hetzner_security.provider_ranges import EDGE_RANGES

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "_output/gallery")
OUT.mkdir(parents=True, exist_ok=True)
WORLD = ["0.0.0.0/0", "::/0"]
LOC = {
    "fsn1": {"name": "fsn1", "network_zone": "eu-central"},
    "nbg1": {"name": "nbg1", "network_zone": "eu-central"},
    "hel1": {"name": "hel1", "network_zone": "eu-central"},
}
TYPES = {name: {"name": name, "cores": cores, "memory": mem, "disk": disk, "architecture": arch, "cpu_type": "shared",
                "deprecated": False, "prices": [{"location": loc, "price_monthly": {"net": str(price)}} for loc in LOC]}
         for name, cores, mem, disk, arch, price in (
             ("cx23", 2, 4, 40, "x86", 4.49), ("cx33", 4, 8, 80, "x86", 7.49), ("cx43", 8, 16, 160, "x86", 13.49),
             ("cpx32", 4, 8, 160, "x86", 14.99), ("cax21", 4, 8, 80, "arm", 7.49), ("ccx23", 4, 16, 160, "x86", 29.99))}


def edge(key: str, count: int = 6) -> list[str]:
    v4 = [value for value in EDGE_RANGES[key]["ranges"] if ":" not in value][:count]
    v6 = [value for value in EDGE_RANGES[key]["ranges"] if ":" in value][:2]
    return v4 + v6


def rule(proto: str, port: int | None, sources: list[str]) -> dict[str, object]:
    return {"direction": "in", "protocol": proto, "port_from": port, "port_to": port, "sources": sources}


class Project:
    def __init__(self, network: tuple[int, str] | None) -> None:
        self.assets: list[dict[str, object]] = []
        self.next_id = 1000
        self.network = network
        if network:
            nid, cidr = network
            self.assets.append({"id": f"hcloud:network:{nid}", "type": "network", "name": "core", "labels": {},
                                "source": "hcloud_api", "properties": {"id": nid, "ip_range": cidr,
                                "subnets": [{"type": "cloud", "ip_range": cidr.replace(".0.0/16", ".1.0/24"), "network_zone": "eu-central"}]}})

    def server(self, name: str, role: str, kind: str, loc: str, rules: list[dict[str, object]], *, private: bool = True,
               public: bool = True, volumes: int = 0, protected: bool = True, env: str = "production", **extra: object) -> str:
        self.next_id += 1
        sid = self.next_id
        props: dict[str, object] = {
            "id": sid, "name": name, "status": "running", "server_type": TYPES[kind], "location": LOC[loc],
            "public_ip": public, "public_ipv4": public, "public_ipv6": public, "firewall_attached": True, "inbound": rules,
            "private_net": [{"network": self.network[0], "ip": f"10.{sid % 200}.1.{sid % 250}"}] if private and self.network else [],
            "volumes": [], "backup_enabled": role in {"db", "replica"}, "delete_protection": protected,
            "protection": {"delete": protected}, **extra,
        }
        if volumes:
            vid = sid * 10
            props["volumes"] = [vid]
            self.assets.append({"id": f"hcloud:volume:{vid}", "type": "volume", "name": f"{name}-data", "labels": {},
                                "source": "hcloud_api", "properties": {"id": vid, "size": volumes, "server": sid}})
        self.assets.append({"id": f"hcloud:server:{sid}", "type": "server", "name": name, "source": "hcloud_api",
                            "labels": {"role": role, "environment": env, "owner": "platform"}, "properties": props})
        return f"hcloud:server:{sid}"

    def lb(self, name: str, loc: str, services: list[tuple[str, int, int]], targets: list[str]) -> None:
        self.next_id += 1
        self.assets.append({"id": f"hcloud:load_balancer:{self.next_id}", "type": "load_balancer", "name": name, "labels": {},
                            "source": "hcloud_api", "properties": {
                                "public_net": {"enabled": True}, "location": LOC[loc],
                                "services": [{"protocol": proto, "listen_port": listen, "destination_port": dest} for proto, listen, dest in services],
                                "targets": [{"type": "server", "server": {"id": int(target.rsplit(":", 1)[-1])}} for target in targets]}})

    def save(self, name: str) -> Path:
        path = OUT / f"{name}.json"
        path.write_text(json.dumps({"schema_version": "1.0.0", "metadata": {"collected_at": "2026-09-23T08:00:00+00:00",
                                    "collector": "hcloud_api", "collector_version": "0.7.0"},
                                    "assets": self.assets, "edges": [], "facts": [], "expectations": [], "signals": []}, indent=1))
        return path


# A: WireGuard admin, Fastly in front of the web tier, one forgotten SSH rule.
a = Project((101, "10.20.0.0/16"))
wg = [rule("udp", 51820, WORLD)]
fastly = edge("fastly")
a.server("web-a", "web", "cx33", "fsn1", [rule("tcp", 443, fastly), rule("tcp", 80, fastly), *wg])
a.server("web-b", "web", "cx33", "nbg1", [rule("tcp", 443, fastly), rule("tcp", 80, fastly), *wg])
a.server("api-1", "api", "cpx32", "fsn1", wg)
a.server("worker-1", "worker", "cax21", "fsn1", wg)
a.server("pg-primary", "db", "ccx23", "fsn1", wg, volumes=200)
a.server("pg-standby", "replica", "ccx23", "nbg1", wg, volumes=200)
a.server("legacy-ftp", "app", "cx23", "nbg1", [rule("tcp", 22, WORLD), rule("tcp", 21, WORLD)], private=False, protected=False, env="staging")
a.save("a-wireguard-fastly")

# B: zero public ingress; Cloudflare Tunnel publishes the apps, Tailscale carries admin traffic.
b = Project((102, "10.30.0.0/16"))
ts = [rule("udp", 41641, WORLD), rule("tcp", 22, ["100.64.0.0/10"])]
tunnel = {"host_agents": ["cloudflared"], "host_evidence": {"bundle_version": 1, "complete": True},
          "host_firewall": {"engine": "ufw", "active": True, "known": True, "world_tcp": "none", "world_tcp_ranges": []}}
b.server("app-1", "app", "cax21", "fsn1", ts, **tunnel)
b.server("app-2", "app", "cax21", "hel1", ts, **tunnel)
b.server("identity-1", "auth", "cx33", "fsn1", ts)
b.server("vault-1", "vault", "cx23", "hel1", ts)
b.server("db-1", "db", "ccx23", "fsn1", ts, volumes=100)
b.server("analytics-1", "analytics", "cx43", "hel1", ts, volumes=400)
b.save("b-zero-ingress")

# C: hybrid: k3s on Cloud behind Bunny CDN, a dedicated database via vSwitch, ZeroTier admin.
c = Project((103, "10.40.0.0/16"))
zt = [rule("udp", 9993, WORLD)]
bunny = edge("bunny")
c.server("k3s-cp-1", "control", "cx33", "fsn1", zt)
c.server("k3s-node-1", "web", "cpx32", "fsn1", [rule("tcp", 443, bunny), *zt])
c.server("k3s-node-2", "web", "cpx32", "nbg1", [rule("tcp", 443, bunny), *zt])
c.server("k3s-node-3", "web", "cpx32", "hel1", [rule("tcp", 443, bunny), rule("tcp", 30000, WORLD), *zt])
c.server("ci-runner", "worker", "cax21", "fsn1", zt, env="staging")
c.save("c-hybrid-k8s")
(OUT / "c-robot.json").write_text(json.dumps({"server": [
    {"server": {"server_number": 5101, "server_name": "db-dedicated", "server_ip": "198.51.100.40", "server_ipv6_net": "2001:db8:40::",
                "product": "AX102", "dc": "FSN1-DC18", "status": "ready", "cancelled": False}},
    {"server": {"server_number": 5102, "server_name": "backup-dedicated", "server_ip": "198.51.100.41", "server_ipv6_net": "2001:db8:41::",
                "product": "SX65", "dc": "FSN1-DC18", "status": "ready", "cancelled": False}}],
    "firewall": {"5101": {"firewall": {"status": "active", "filter_ipv6": True, "rules": {"input": [
        {"ip_version": "ipv4", "src_ip": None, "dst_port": "9993", "protocol": "udp", "action": "accept"}]}}},
                 "5102": {"firewall": {"status": "disabled", "filter_ipv6": False, "rules": {"input": []}}}},
    "vswitch": [{"id": 77, "name": "cloud-link", "vlan": 4010, "server": [{"server_number": 5101}, {"server_number": 5102}],
                 "cloud_network": [{"id": 103}]}], "key": []}))
(OUT / "c-k8s.json").write_text(json.dumps({"kind": "List", "items": [
    *({"kind": "Node", "metadata": {"name": name, "labels": {"node-role.kubernetes.io/control-plane": "true"} if "cp" in name else {}},
       "spec": {}, "status": {"nodeInfo": {"kubeletVersion": "v1.31.4+k3s1"}}} for name in ("k3s-cp-1", "k3s-node-1", "k3s-node-2", "k3s-node-3")),
    {"kind": "Pod", "metadata": {"namespace": "kube-system", "name": "hcloud-cloud-controller-manager-x", "ownerReferences": [{"kind": "ReplicaSet", "name": "hcloud-cloud-controller-manager-7d"}]},
     "spec": {"nodeName": "k3s-cp-1", "containers": [{"name": "ccm", "image": "hetznercloud/hcloud-cloud-controller-manager:v1.21.0"}]}},
    {"kind": "Pod", "metadata": {"namespace": "shop", "name": "builder-x", "ownerReferences": [{"kind": "ReplicaSet", "name": "builder-6c"}]},
     "spec": {"nodeName": "k3s-node-3", "containers": [{"name": "b", "image": "docker:27-dind", "securityContext": {"privileged": True}}]}},
    {"kind": "Service", "metadata": {"namespace": "shop", "name": "debug"}, "spec": {"type": "NodePort", "ports": [{"port": 80, "nodePort": 30000, "protocol": "TCP"}]}},
]}))

# D: multi-location load balancer behind CloudFront, NetBird admin, Object Storage.
d = Project((104, "10.50.0.0/16"))
nb = [rule("udp", 51820, WORLD), rule("tcp", 22, ["100.64.0.0/10"])]
cloudfront = edge("cloudfront")
web = [d.server(f"web-{index}", "web", "cx33", loc, [rule("tcp", 443, cloudfront), *nb]) for index, loc in ((1, "fsn1"), (2, "nbg1"), (3, "hel1"))]
d.lb("edge-lb", "fsn1", [("https", 443, 8443)], web)
d.server("queue-1", "bus", "cx23", "fsn1", nb)
d.server("search-1", "data", "cx43", "nbg1", [rule("tcp", 9200, WORLD), *nb], volumes=300)
d.server("db-main", "db", "ccx23", "fsn1", nb, volumes=250)
d.save("d-lb-cloudfront")
(OUT / "d-buckets.json").write_text(json.dumps({"buckets": [
    {"name": "static-assets", "location": "fsn1", "acl": [{"grantee": "AllUsers", "permission": "READ"}], "policy": None, "versioning": "Off",
     "anonymous_list": True, "reads": {"acl": True, "policy": True, "versioning": True}},
    {"name": "db-backups", "location": "nbg1", "acl": [], "policy": None, "versioning": "Enabled", "reads": {"acl": True, "policy": True, "versioning": True}},
    {"name": "user-uploads", "location": "fsn1", "acl": [], "policy": None, "versioning": "Enabled", "reads": {"acl": True, "policy": True, "versioning": True}}]}))
print(f"wrote examples to {OUT}")
