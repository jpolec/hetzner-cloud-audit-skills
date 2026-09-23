"""Kubernetes correlation rules (``--k8s``): NodePorts the Cloud Firewall opens to the Internet,
and workloads that break out to the node (privileged, host namespaces, host paths).
"""

from __future__ import annotations

from ..flows import PortSet, asset_exposure
from ..graph import AttackGraph
from ..models import Finding, Severity, Snapshot
from .rules import _candidate, _evidence


def _world(server_props: dict[str, object], exposure: dict[tuple[str, str, str], PortSet], protocol: str) -> PortSet:
    if server_props.get("public_ip") is False:
        return PortSet()  # no public interface: nothing reaches the node from the Internet
    if server_props.get("public_ip", True) and server_props.get("firewall_attached") is False:
        return PortSet.full()
    return PortSet.of([span for (_f, proto, klass), ports in exposure.items() if proto == protocol and klass == "world" for span in ports])


def node_port_exposure(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    """HETZ-K8S-001: a NodePort is admitted from the Internet on nodes, bypassing any load balancer."""
    nodes = [asset for asset in snapshot.assets if asset.type == "server" and asset.properties.get("k8s")]
    output: list[Finding] = []
    for service in snapshot.assets:
        if service.type != "k8s_service":
            continue
        open_on: list[tuple[str, int]] = []
        for node in nodes:
            exposure = asset_exposure(node, snapshot.edges)
            for port in service.properties.get("ports") or []:
                node_port = port.get("node_port")
                if isinstance(node_port, int) and node_port in _world(node.properties, exposure, str(port.get("protocol", "tcp"))):
                    open_on.append((node.id, node_port))
        if not open_on:
            continue
        ports = sorted({port for _, port in open_on})
        behind_lb = service.properties.get("hcloud_load_balancer") or service.properties.get("type") == "LoadBalancer"
        output.append(
            _candidate(
                "HETZ-K8S-001",
                f"NodePort of {service.name} is open to the Internet on {len({node for node, _ in open_on})} node(s)",
                Severity.HIGH if not behind_lb else Severity.MEDIUM,
                0.9,
                [service.id, *sorted({node for node, _ in open_on})],
                f"{service.properties.get('type')} service; kube-proxy listens on node ports {ports} on every node, and the Cloud Firewall admits them from anywhere.",
                "Node ports accept traffic only from the load balancer or private network.",
                f"node ports {ports} world-open on {sorted({node for node, _ in open_on})}",
                [_evidence(service, "node_port", service.properties.get("ports"), "properties.ports")],
                ["internet", *(f"tcp/{port}" for port in ports[:2]), service.id],
                [],
                "Clients reach the service directly on every node, skipping the load balancer's TLS, rate limits, and health checks." if behind_lb
                else "The service is reachable on every node's public address.",
                "Restrict the node-port range (30000-32767) in the Cloud Firewall to the load balancer's private network; use the LB's private targets.",
                ["https://github.com/hetznercloud/hcloud-cloud-controller-manager/blob/main/docs/load_balancers.md"],
                ",".join(map(str, ports)),
            )
        )
    return output


def workload_breakout(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    """HETZ-K8S-002: workloads with node-level access (privileged, host namespaces, sensitive host paths)."""
    output: list[Finding] = []
    for workload in snapshot.assets:
        if workload.type != "k8s_workload":
            continue
        props = workload.properties
        reasons = [name for name in ("privileged", "host_pid", "host_network", "host_ipc") if props.get(name)]
        if props.get("sensitive_host_paths"):
            reasons.append(f"hostPath {props['sensitive_host_paths']}")
        if props.get("capabilities"):
            reasons.append(f"capabilities {props['capabilities']}")
        if not reasons:
            continue
        output.append(
            _candidate(
                "HETZ-K8S-002",
                f"Workload {workload.name} has node-level access",
                Severity.LOW if props.get("system") else Severity.HIGH,
                0.9,
                [workload.id],
                f"{props.get('pods')} pod(s) on {len(props.get('nodes') or [])} node(s): {', '.join(reasons)}.",
                "Application workloads run unprivileged, without host namespaces or host paths.",
                "; ".join(reasons),
                [_evidence(workload, "pod_security", {key: props.get(key) for key in ("privileged", "host_pid", "host_network", "sensitive_host_paths", "capabilities")}, "properties")],
                [workload.id, "node"],
                ["Code execution in one of the pods."],
                "A compromised pod controls the node and everything scheduled on it, including other tenants' secrets.",
                "Drop privileged and host settings; enforce the 'restricted' Pod Security Standard on application namespaces.",
                ["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
            )
        )
    return output


K8S_RULES = (node_port_exposure, workload_breakout)
