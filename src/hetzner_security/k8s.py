"""Kubernetes on Hetzner, correlation only: ``kubectl get nodes,pods,services -A -o json``.

The audit never talks to the cluster. The owner saves the listing; this module maps nodes to
Hetzner servers (``spec.providerID`` ``hcloud://ID``, else the node name), records risky
workloads (privileged, host namespaces, host paths), and NodePort/LoadBalancer services, so
the Cloud Firewall on the nodes can be checked against what Kubernetes opens on every node.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from .models import Asset, Edge, Evidence, Snapshot

MAX_K8S_BYTES = 256 * 1024 * 1024
SYSTEM_NAMESPACES = {"kube-system", "kube-public", "kube-node-lease", "cilium", "calico-system", "tigera-operator",
                     "longhorn-system", "cert-manager", "ingress-nginx", "traefik", "monitoring", "system-upgrade"}
SENSITIVE_HOST_PATHS = ("/", "/etc", "/root", "/home", "/proc", "/sys", "/dev", "/boot", "/var/lib/kubelet", "/var/lib/docker")
# Container runtime sockets and their directories: any path under these controls the node.
RUNTIME_PREFIXES = ("/var/run/docker.sock", "/run/docker.sock", "/run/containerd", "/var/run/containerd", "/run/crio", "/var/run/crio", "/run/k3s", "/var/run/k3s")


def _sensitive_path(path: str) -> bool:
    normalized = "/" + path.strip("/") if path.strip("/") else "/"
    return normalized in SENSITIVE_HOST_PATHS or normalized.startswith(RUNTIME_PREFIXES)
INTEGRATIONS = {
    "hcloud-cloud-controller-manager": "Hetzner CCM",
    "hcloud-csi": "Hetzner CSI",
    "kube-hetzner": "kube-hetzner",
    "rancher/k3s": "k3s",
}


def load_k8s(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_K8S_BYTES:
        raise ValueError(f"Kubernetes listing {path} exceeds {MAX_K8S_BYTES} bytes")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("items"), list):
        raise ValueError(f"{path} must be `kubectl get nodes,pods,services -A -o json` output (a List with items)")
    return raw


def _owner(pod: dict[str, Any]) -> str:
    meta = pod.get("metadata") or {}
    owners = meta.get("ownerReferences") or []
    if owners:
        owner = owners[0]
        name = str(owner.get("name", ""))
        if owner.get("kind") == "ReplicaSet" and name.count("-") >= 1:
            return "Deployment/" + name.rsplit("-", 1)[0]
        return f"{owner.get('kind')}/{name}"
    return f"Pod/{meta.get('name')}"


def _pod_risks(pod: dict[str, Any]) -> dict[str, Any]:
    spec = pod.get("spec") or {}
    containers = [*(spec.get("containers") or []), *(spec.get("initContainers") or [])]
    privileged = any((container.get("securityContext") or {}).get("privileged") for container in containers)
    caps = sorted({str(cap) for container in containers for cap in ((container.get("securityContext") or {}).get("capabilities") or {}).get("add") or []})
    host_paths = sorted({str((volume.get("hostPath") or {}).get("path")) for volume in spec.get("volumes") or [] if volume.get("hostPath")})
    host_ports = sorted({int(port["hostPort"]) for container in containers for port in container.get("ports") or [] if port.get("hostPort")})
    return {
        "privileged": privileged,
        "host_network": bool(spec.get("hostNetwork")),
        "host_pid": bool(spec.get("hostPID")),
        "host_ipc": bool(spec.get("hostIPC")),
        "capabilities": caps,
        "host_paths": host_paths,
        "sensitive_host_paths": [path for path in host_paths if _sensitive_path(path)],
        "host_ports": host_ports,
        "images": sorted({str(container.get("image")) for container in containers}),
    }


def apply_k8s(snapshot: Snapshot, raw: dict[str, Any], cluster: str = "cluster") -> Snapshot:
    result = deepcopy(snapshot)
    servers = {asset.id: asset for asset in result.assets if asset.type == "server"}
    by_name = {asset.name: asset for asset in servers.values()}
    items = raw["items"]
    nodes = [item for item in items if item.get("kind") == "Node"]
    pods = [item for item in items if item.get("kind") == "Pod"]
    services = [item for item in items if item.get("kind") == "Service"]
    cluster_id = f"k8s:cluster:{cluster}"
    node_servers: dict[str, str] = {}
    unmatched: list[str] = []
    for node in nodes:
        meta = node.get("metadata") or {}
        name = str(meta.get("name"))
        provider = str((node.get("spec") or {}).get("providerID") or "")
        server = servers.get(f"hcloud:server:{provider.removeprefix('hcloud://')}") if provider.startswith("hcloud://") else None
        server = server or by_name.get(name)
        if server is None:
            unmatched.append(name)
            continue
        labels = meta.get("labels") or {}
        role = "control-plane" if any(key in labels for key in ("node-role.kubernetes.io/control-plane", "node-role.kubernetes.io/master")) else "worker"
        server.properties["k8s"] = {
            "cluster": cluster, "node": name, "role": role,
            "kubelet": ((node.get("status") or {}).get("nodeInfo") or {}).get("kubeletVersion"),
        }
        node_servers[name] = server.id
        result.edges.append(Edge(cluster_id, server.id, "runs"))

    workloads: dict[str, dict[str, Any]] = {}
    integrations: set[str] = set()
    for pod in pods:
        meta = pod.get("metadata") or {}
        risks = _pod_risks(pod)
        for image in risks["images"]:
            integrations.update(label for token, label in INTEGRATIONS.items() if token in image)
        namespace = str(meta.get("namespace"))
        key = f"{namespace}/{_owner(pod)}"
        workload = workloads.setdefault(key, {"namespace": namespace, "owner": _owner(pod), "system": namespace in SYSTEM_NAMESPACES,
                                              "pods": 0, "nodes": set(), **{k: v for k, v in risks.items() if k != "images"}, "images": risks["images"]})
        workload["pods"] += 1
        # Pods of one workload normally share a template; if they differ, keep the riskiest view.
        for flag in ("privileged", "host_network", "host_pid", "host_ipc"):
            workload[flag] = workload[flag] or risks[flag]
        for key in ("capabilities", "host_paths", "sensitive_host_paths", "host_ports"):
            workload[key] = sorted(set(workload[key]) | set(risks[key]))
        node = (pod.get("spec") or {}).get("nodeName")
        if node:
            workload["nodes"].add(node)

    assets = [Asset(cluster_id, "k8s_cluster", cluster, {"nodes": len(nodes), "matched_nodes": len(node_servers),
                                                         "integrations": sorted(integrations)}, {}, "kubernetes")]
    for key, workload in sorted(workloads.items()):
        risky = (workload["privileged"] or workload["host_pid"] or workload["host_network"] or workload["host_ipc"]
                 or workload["sensitive_host_paths"] or workload["capabilities"])
        if not risky:
            continue
        asset_id = f"k8s:workload:{cluster}:{key}"
        assets.append(Asset(asset_id, "k8s_workload", key, {**workload, "nodes": sorted(workload["nodes"])}, {}, "kubernetes"))
        for node in workload["nodes"]:
            if node in node_servers:
                result.edges.append(Edge(node_servers[node], asset_id, "runs"))
    for service in services:
        meta, spec = service.get("metadata") or {}, service.get("spec") or {}
        if spec.get("type") not in {"NodePort", "LoadBalancer"}:
            continue
        ports = [
            {"port": port.get("port"), "node_port": port.get("nodePort"), "protocol": str(port.get("protocol", "TCP")).lower()}
            for port in spec.get("ports") or [] if port.get("nodePort")
        ]
        annotations = meta.get("annotations") or {}
        asset_id = f"k8s:service:{cluster}:{meta.get('namespace')}/{meta.get('name')}"
        assets.append(Asset(asset_id, "k8s_service", f"{meta.get('namespace')}/{meta.get('name')}", {
            "type": spec.get("type"), "ports": ports, "namespace": meta.get("namespace"),
            "hcloud_load_balancer": any(key.startswith("load-balancer.hetzner.cloud/") for key in annotations),
            "external_traffic_policy": spec.get("externalTrafficPolicy"),
        }, {}, "kubernetes"))
        for server_id in node_servers.values():
            for port in ports:
                evidence = (Evidence("kubernetes", "node_port", asset_id, port, "spec.ports"),)
                result.edges.append(Edge(server_id, asset_id, "publishes", port["protocol"], port["node_port"], evidence))
    result.assets.extend(assets)
    result.metadata["kubernetes"] = {
        "cluster": cluster, "nodes": len(nodes), "matched_nodes": sorted(node_servers), "unmatched_nodes": unmatched,
        "pods": len(pods), "services": len(services), "integrations": sorted(integrations),
    }
    return result
