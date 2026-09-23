"""Generated-infrastructure benchmark: random projects with planted issues and known ground truth.

Each generated project mixes planted problems with clean twins (the safe variant of the same
configuration). Detection is scored per (rule, asset): true positives, false positives, and
false negatives. This measures the rules against their own specification on synthetic data;
it is not a measure of real-world prevalence.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from typing import Any

from .analyzers import hunt
from .models import Asset, Snapshot
from .verification import verify_all

WORLD = ["0.0.0.0/0", "::/0"]
CF = ["173.245.48.0/20", "103.21.244.0/22"]


def _rule(protocol: str, first: int | None, last: int | None, sources: list[str]) -> dict[str, Any]:
    return {"direction": "in", "protocol": protocol, "port_from": first, "port_to": last, "sources": sources}


class _Project:
    def __init__(self, rng: random.Random, index: int) -> None:
        self.rng = rng
        self.index = index
        self.assets: list[Asset] = []
        self.truth: set[tuple[str, str]] = set()
        self.counter = 0

    def _id(self, kind: str) -> str:
        self.counter += 1
        return f"hcloud:{kind}:{self.index}-{self.counter}"

    def server(self, rules: list[dict[str, Any]], *, labels: dict[str, str] | None = None, firewall: bool = True,
               protected: bool = True, image: str = "24.04") -> Asset:
        asset_id = self._id("server")
        base_labels = {"environment": "production", "role": "app", "owner": "team", "project": "p"}
        asset = Asset(
            asset_id, "server", asset_id.split(":")[-1].replace("-", "x"),
            {
                "public_ip": True, "firewall_attached": firewall, "inbound": rules if firewall else [],
                "protection": {"delete": protected}, "delete_protection": protected,
                "image": {"os_flavor": "ubuntu", "os_version": image, "name": f"ubuntu-{image}"},
                "server_type": {"name": "cx23", "deprecated": False},
            },
            base_labels if labels is None else labels, "hcloud_api",
        )
        self.assets.append(asset)
        return asset

    def firewall(self, rules: list[dict[str, Any]], attached: bool = True) -> Asset:
        asset_id = self._id("firewall")
        asset = Asset(asset_id, "firewall", asset_id.split(":")[-1], {
            "inbound": rules,
            "applied_to": [{"type": "server", "server": {"id": 1}}] if attached else [],
        }, {}, "hcloud_api")
        self.assets.append(asset)
        return asset

    def plant(self, rule_id: str, asset: Asset) -> None:
        self.truth.add((rule_id, asset.id))


Scenario = Callable[[_Project, bool], None]


def _ssh(project: _Project, bad: bool) -> None:
    if not bad and project.rng.random() < 0.5:
        # Clean twin: the same world-open rule on a server without a public interface is not exposure.
        server = project.server([_rule("tcp", 22, 22, WORLD)])
        server.properties.update({"public_ip": False, "public_ipv4": False, "public_ipv6": False})
        return
    server = project.server([_rule("tcp", 22, 22, WORLD if bad else ["100.64.0.0/10"])])
    if bad:
        project.plant("HETZ-NET-001", server)


def _postgres(project: _Project, bad: bool) -> None:
    server = project.server([_rule("tcp", 5432, 5432, WORLD if bad else ["10.0.0.0/16"])])
    if bad:
        project.plant("HETZ-NET-003", server)


def _all_ports(project: _Project, bad: bool) -> None:
    firewall = project.firewall([_rule("tcp", None, None, WORLD) if bad else _rule("tcp", 443, 443, WORLD)])
    if bad:
        project.plant("HETZ-FW-001", firewall)


def _ipv6_drift(project: _Project, bad: bool) -> None:
    firewall = project.firewall([_rule("tcp", 8443, 8443, ["::/0"] if bad else WORLD)])
    if bad:
        project.plant("HETZ-FW-003", firewall)


def _unattached(project: _Project, bad: bool) -> None:
    firewall = project.firewall([_rule("tcp", 443, 443, WORLD)], attached=not bad)
    if bad:
        project.plant("HETZ-FW-002", firewall)


def _no_firewall(project: _Project, bad: bool) -> None:
    # 8443, not 443: a world-open 443 next to Cloudflare-only peers is itself HETZ-NET-006.
    server = project.server([_rule("tcp", 8443, 8443, WORLD)], firewall=not bad)
    if bad:
        project.plant("HETZ-NET-005", server)


def _cloudflare_bypass(project: _Project, bad: bool) -> None:
    project.server([_rule("tcp", 443, 443, CF)])  # a Cloudflare-fronted peer
    server = project.server([_rule("tcp", 443, 443, WORLD if bad else CF)])
    if bad:
        project.plant("HETZ-NET-006", server)


def _unlabeled(project: _Project, bad: bool) -> None:
    labels = {"owner": "team", "project": "p"} if bad else {"environment": "production", "role": "app", "owner": "team", "project": "p"}
    server = project.server([], labels=labels)
    if bad:
        project.plant("HETZ-GOV-004", server)


def _weak_key(project: _Project, bad: bool) -> None:
    asset_id = project._id("ssh_key")
    key = Asset(asset_id, "ssh_key", asset_id.split(":")[-1], {
        "key_type": "ssh-rsa" if bad else "ssh-ed25519", "key_bits": 2048 if bad else 256, "created": "2026-01-01T00:00:00+00:00",
    }, {}, "hcloud_api")
    project.assets.append(key)
    if bad:
        project.plant("HETZ-KEY-001", key)


def _storage_box(project: _Project, bad: bool) -> None:
    asset_id = project._id("storage_box")
    box = Asset(asset_id, "storage_box", asset_id.split(":")[-1], {
        "access_settings": {"ssh_enabled": True, "reachable_externally": bad},
        "snapshot_plan": {"max_snapshots": 7}, "protection": {"delete": True},
    }, {}, "hcloud_api")
    project.assets.append(box)
    if bad:
        project.plant("HETZ-STO-001", box)


def _host(server: Asset, **props: Any) -> None:
    server.properties.update({"host_evidence": {"bundle_version": 1, "complete": True}, **props})


def _docker_bypass(project: _Project, bad: bool) -> None:
    server = project.server([_rule("tcp", 8443, 8443, WORLD)])  # not 443: see _no_firewall
    _host(
        server,
        host_firewall={"engine": "ufw", "active": True, "world_tcp": "8443", "world_tcp_ranges": [[8443, 8443]]},
        docker_published=[{"container": "api", "host_port": 9001, "protocol": "tcp", "bind": "wildcard" if bad else "loopback",
                           "host_ip": "0.0.0.0" if bad else "127.0.0.1"}],
        docker_user_filters=False,
    )
    if bad:
        project.plant("HETZ-DKR-005", server)


def _ssh_password(project: _Project, bad: bool) -> None:
    server = project.server([_rule("tcp", 22, 22, ["100.64.0.0/10"])])
    _host(server, sshd={"port": ["22"], "passwordauthentication": "yes" if bad else "no", "permitrootlogin": "prohibit-password"})
    if bad:
        project.plant("HETZ-SSH-001", server)


def _no_host_firewall(project: _Project, bad: bool) -> None:
    server = project.server([_rule("tcp", 8443, 8443, WORLD)])
    _host(server, host_firewall={"engine": "nftables", "active": not bad, "world_tcp": "all" if bad else "8443",
                                 "world_tcp_ranges": [[0, 65535]] if bad else [[8443, 8443]]})
    if bad:
        project.plant("HETZ-HOST-001", server)


def _wide_bind(project: _Project, bad: bool) -> None:
    server = project.server([_rule("tcp", 8443, 8443, WORLD)])
    _host(server, listeners=[{"protocol": "tcp", "port": 5432, "address": "0.0.0.0" if bad else "127.0.0.1",
                              "bind": "wildcard" if bad else "loopback", "process": "postgres"}])
    if bad:
        project.plant("HETZ-HOST-002", server)


def _pg_remote_auth(project: _Project, bad: bool) -> None:
    asset_id = project._id("postgres")
    entries = [{"type": "hostssl" if not bad else "host", "database": "all", "user": "all", "address": "0.0.0.0/0", "method": "scram-sha-256"}]
    pg = Asset(asset_id, "postgres", asset_id.split(":")[-1], {"pg_hba": entries, "port": 5432}, {}, "host_bundle")
    project.assets.append(pg)
    if bad:
        project.plant("HETZ-PG-003", pg)


def _robot_ipv6(project: _Project, bad: bool) -> None:
    asset_id = project._id("robot_server")
    firewall = {"present": True, "status": "active", "filter_ipv6": not bad, "rules": [
        {"ip_version": "ipv4", "src_ip": None, "dst_port": "443", "protocol": "tcp", "action": "accept"}]}
    server = Asset(asset_id, "robot_server", asset_id.split(":")[-1], {"server_ipv6_net": "2001:db8::", "robot_firewall": firewall}, {}, "robot_api")
    project.assets.append(server)
    if bad:
        project.plant("HETZ-ROB-005", server)


def _public_bucket(project: _Project, bad: bool) -> None:
    asset_id = project._id("bucket")
    acl = [{"grantee": "account", "permission": "FULL_CONTROL"}, *([{"grantee": "AllUsers", "permission": "READ"}] if bad else [])]
    bucket = Asset(asset_id, "bucket", asset_id.split(":")[-1], {"acl": acl, "policy": None, "versioning": "Enabled"}, {}, "object_storage_api")
    project.assets.append(bucket)
    if bad:
        project.plant("HETZ-OBJ-001", bucket)


def _pod_breakout(project: _Project, bad: bool) -> None:
    asset_id = project._id("k8s_workload")
    workload = Asset(asset_id, "k8s_workload", asset_id.split(":")[-1], {
        "namespace": "shop", "system": False, "pods": 2, "nodes": [], "privileged": bad, "host_pid": False,
        "host_network": False, "host_ipc": False, "sensitive_host_paths": [], "capabilities": []}, {}, "kubernetes")
    project.assets.append(workload)
    if bad:
        project.plant("HETZ-K8S-002", workload)


SCENARIOS: dict[str, Scenario] = {
    "HETZ-NET-001": _ssh,
    "HETZ-NET-003": _postgres,
    "HETZ-FW-001": _all_ports,
    "HETZ-FW-003": _ipv6_drift,
    "HETZ-FW-002": _unattached,
    "HETZ-NET-005": _no_firewall,
    "HETZ-NET-006": _cloudflare_bypass,
    "HETZ-GOV-004": _unlabeled,
    "HETZ-KEY-001": _weak_key,
    "HETZ-STO-001": _storage_box,
    "HETZ-DKR-005": _docker_bypass,
    "HETZ-SSH-001": _ssh_password,
    "HETZ-HOST-001": _no_host_firewall,
    "HETZ-HOST-002": _wide_bind,
    "HETZ-PG-003": _pg_remote_auth,
    "HETZ-ROB-005": _robot_ipv6,
    "HETZ-OBJ-001": _public_bucket,
    "HETZ-K8S-002": _pod_breakout,
}


def generate(seed: int, count: int) -> list[tuple[Snapshot, set[tuple[str, str]]]]:
    rng = random.Random(seed)  # noqa: S311 -- deterministic benchmark data, not cryptography
    projects = []
    for index in range(count):
        project = _Project(rng, index)
        for scenario in SCENARIOS.values():
            for _ in range(rng.randint(0, 2)):
                scenario(project, rng.random() < 0.5)
        projects.append((Snapshot(assets=project.assets, metadata={"collected_at": "2026-09-23T00:00:00+00:00"}), project.truth))
    return projects


def score(seed: int = 20260923, count: int = 150) -> dict[str, dict[str, int]]:
    """TP/FP/FN per benchmarked rule over `count` generated projects."""
    results = {rule: {"tp": 0, "fp": 0, "fn": 0, "planted": 0} for rule in SCENARIOS}
    for snapshot, truth in generate(seed, count):
        findings = verify_all(hunt(snapshot), snapshot)
        reported = {(item.rule_id, asset) for item in findings if item.rule_id in SCENARIOS for asset in item.assets}
        for rule in SCENARIOS:
            planted = {pair for pair in truth if pair[0] == rule}
            found = {pair for pair in reported if pair[0] == rule}
            results[rule]["planted"] += len(planted)
            results[rule]["tp"] += len(planted & found)
            results[rule]["fp"] += len(found - planted)
            results[rule]["fn"] += len(planted - found)
    return results


def render_score_markdown(results: dict[str, dict[str, int]], seed: int, count: int) -> str:
    lines = [
        f"Generated benchmark: {count} projects, seed {seed}. Each planted issue has a clean twin in the same run.",
        "",
        "| Rule | Planted | True positives | False positives | False negatives | Precision | Recall |",
        "|---|---|---|---|---|---|---|",
    ]
    for rule, value in results.items():
        precision = value["tp"] / (value["tp"] + value["fp"]) if value["tp"] + value["fp"] else 1.0
        recall = value["tp"] / value["planted"] if value["planted"] else 1.0
        lines.append(f"| {rule} | {value['planted']} | {value['tp']} | {value['fp']} | {value['fn']} | {precision:.2f} | {recall:.2f} |")
    return "\n".join(lines)
