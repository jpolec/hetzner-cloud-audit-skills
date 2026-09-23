"""Safe local CLI for evidence-backed Hetzner infrastructure audits."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from ..actions import build_actions
from ..analyzers import hunt
from ..attestations import apply_attestations, load_attestations, render_checklist_markdown
from ..attestations import template as attestation_template
from ..collectors.fixture import load_snapshot
from ..collectors.hcloud import HCloudCollectionError, ReadOnlyHCloudCollector
from ..collectors.objectstorage import (
    ObjectStorageError,
    ReadOnlyObjectStorageCollector,
    apply_object_storage,
    load_object_storage_file,
)
from ..collectors.robot import (
    ReadOnlyRobotCollector,
    RobotCollectionError,
    apply_robot,
    load_robot_file,
)
from ..cost import analyze_cost, render_cost_markdown
from ..coverage import plan_coverage, render_coverage, save_coverage, update_coverage
from ..diagram import (
    posture_matrix,
    render_connectivity_svg,
    render_cost_svg,
    render_host_svg,
    render_posture_svg,
    render_svg,
)
from ..doctor import render_doctor_markdown, run_doctor
from ..findings import render_json, render_markdown, render_sarif
from ..findings.summary import build_summary, host_rows, other_sources
from ..findings.suppress import apply_suppressions
from ..graph import AttackGraph, render_path_markdown
from ..host import BUNDLE_SCRIPT, apply_host_bundles, parse_bundle
from ..iac import apply_terraform
from ..k8s import apply_k8s, load_k8s
from ..models import Finding, FindingStatus, Severity, Snapshot
from ..node_metrics import (
    NODE_METRICS_EXAMPLE,
    QUERIES,
    apply_node_metrics,
    collect_prometheus,
    load_node_metrics,
)
from ..policy import apply_policy, load_policy
from ..projects import merge_snapshots, tag_project
from ..temporal import diff_snapshots, render_diff_markdown
from ..text import md
from ..topology import build_topology, render_mermaid, render_topology_markdown
from ..verification import verify_all

SEVERITY_ORDER = {severity.value: index for index, severity in enumerate(Severity)}


def _common(cmd: argparse.ArgumentParser, *, formats: tuple[str, ...] = ("json", "markdown", "sarif")) -> None:
    cmd.add_argument("--input", type=Path, help="Normalized snapshot; avoids live API access")
    cmd.add_argument("--format", choices=formats, default="markdown")
    cmd.add_argument("--output", type=Path)
    cmd.add_argument("--read-only", action=argparse.BooleanOptionalAction, default=True)
    cmd.add_argument("--no-ssh", action="store_true", default=True)
    cmd.add_argument("--no-external-tools", action="store_true")
    cmd.add_argument("--dry-run", action="store_true")
    cmd.add_argument("--policy", type=Path, help="Owner policy in JSON or TOML")
    cmd.add_argument("--project", help="Name this Hetzner project in the snapshot (for multi-project reports)")
    cmd.add_argument("--token-env", default="HCLOUD_TOKEN", help="Environment variable that holds this project's read-only token")
    cmd.add_argument("--node-metrics", type=Path, help="Guest RAM/disk telemetry JSON (see `hetzner-audit metrics`)")
    cmd.add_argument(
        "--robot",
        nargs="?",
        const="live",
        help="Add Hetzner Robot (dedicated servers): a saved responses file, or no value for live read-only GETs "
        "with HROBOT_USER/HROBOT_PASSWORD",
    )
    cmd.add_argument(
        "--object-storage",
        nargs="?",
        const="live",
        help="Add Object Storage buckets: a saved file, or no value for live signed GETs with "
        "HETZNER_S3_ACCESS_KEY/HETZNER_S3_SECRET_KEY",
    )
    cmd.add_argument("--k8s", type=Path, help="`kubectl get nodes,pods,services -A -o json` output for Kubernetes correlation")
    cmd.add_argument("--k8s-cluster", default="cluster", help="Name for the cluster in the report")
    cmd.add_argument("--attestations", type=Path, help="Owner answers to the console checklist (see `hetzner-audit checklist`)")
    cmd.add_argument("--terraform", type=Path, help="`terraform show -json` output (state or saved plan) for drift")
    cmd.add_argument(
        "--host-bundle",
        type=Path,
        action="append",
        default=[],
        help="Host evidence bundle from `hetzner-audit host-bundle` output run on a server (repeatable)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hetzner-audit", description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("audit", "inventory", "network", "postgres", "docker", "coverage", "snapshot"):
        cmd = subparsers.add_parser(name)
        _common(cmd)
        cmd.add_argument("--severity", choices=tuple(SEVERITY_ORDER), default="info")
        cmd.add_argument("--verify", action=argparse.BooleanOptionalAction, default=True)
        cmd.add_argument("--coverage-ledger", type=Path)
        cmd.add_argument(
            "--fail-on",
            choices=("none", "confirmed", "confirmed-high"),
            default="none",
            help="Exit 1 on confirmed findings (any severity, or high/critical only). needs_validation never fails.",
        )

    cost = subparsers.add_parser("cost")
    _common(cost, formats=("json", "markdown"))
    cost.add_argument("--metrics-days", type=int, default=30)

    path = subparsers.add_parser("path")
    _common(path, formats=("json", "markdown"))
    path.add_argument("--from", dest="path_source", required=True)
    path.add_argument("--to", dest="path_target", required=True)
    path.add_argument("--protocol", choices=("tcp", "udp", "icmp"), default="tcp")
    path.add_argument("--port", type=int)
    path.add_argument("--max-depth", type=int, default=6)

    merge = subparsers.add_parser("merge", help="Combine per-project snapshots into one multi-project snapshot")
    merge.add_argument("snapshots", type=Path, nargs="+")
    merge.add_argument("--output", type=Path)

    diff = subparsers.add_parser("diff")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    diff.add_argument("--format", choices=("json", "markdown"), default="markdown")
    diff.add_argument("--output", type=Path)
    diff.add_argument("--fail-on-regression", action="store_true")

    explain = subparsers.add_parser("explain")
    explain.add_argument("finding_id")
    _common(explain, formats=("json", "markdown"))

    ask = subparsers.add_parser("ask")
    ask.add_argument("question")
    _common(ask, formats=("json", "markdown"))

    doctor = subparsers.add_parser("doctor", help="Check token, API access, scope, tools, and report privacy")
    doctor.add_argument("--format", choices=("markdown", "json"), default="markdown")
    doctor.add_argument("--output", type=Path)
    doctor.add_argument("--report-dir", type=Path, default=Path("."), help="Where you plan to write reports")

    checklist = subparsers.add_parser("checklist", help="Console checks no API exposes (members, 2FA, token scopes)")
    checklist.add_argument("--template", action="store_true", help="Print an answers file to fill in")
    checklist.add_argument("--output", type=Path)

    metrics = subparsers.add_parser("metrics", help="Build the guest RAM/disk telemetry file from Prometheus (read-only queries)")
    metrics.add_argument("--prometheus", help="Prometheus base URL; PROMETHEUS_TOKEN is sent as a bearer token if set")
    metrics.add_argument("--days", type=int, default=30)
    metrics.add_argument("--example", action="store_true", help="Print the file format instead of querying")
    metrics.add_argument("--queries", action="store_true", help="Print the PromQL queries instead of running them")
    metrics.add_argument("--output", type=Path)

    bundle = subparsers.add_parser("host-bundle", help="Print the read-only host evidence script, or parse a bundle")
    bundle.add_argument("--parse", type=Path, help="Show what the audit reads from a collected bundle")
    bundle.add_argument("--output", type=Path)

    topology = subparsers.add_parser("map", help="Network map as Markdown/Mermaid, SVG, or JSON")
    _common(topology, formats=("markdown", "mermaid", "svg", "json"))
    topology.add_argument("--title", default="Hetzner Cloud architecture")
    topology.add_argument("--theme", choices=("light", "dark"), default="light", help="SVG color theme")
    topology.add_argument(
        "--view",
        choices=("architecture", "connectivity", "cost", "host", "posture"),
        default="architecture",
        help="SVG view: architecture, per-VM connectivity, per-VM cost, per-VM host layers (needs --host-bundle), or posture matrix",
    )
    topology.add_argument("--max-actions", type=int, default=6, help="Recommended actions drawn on the SVG (0 hides them)")
    return parser


def _snapshot(args: argparse.Namespace) -> Snapshot:
    if not args.read_only:
        raise ValueError("v0.3 supports read-only mode only")
    if args.input:
        snapshot = load_snapshot(args.input)
    elif args.dry_run:
        snapshot = Snapshot(metadata={"dry_run": True, "planned_collector": "hcloud_api_get_only"})
    else:
        snapshot = ReadOnlyHCloudCollector(
            os.environ.get(args.token_env) or None,
            include_metrics=args.command == "cost" or getattr(args, "view", None) == "cost",
            metrics_days=getattr(args, "metrics_days", 30),
        ).collect()
    if args.project:
        snapshot = tag_project(snapshot, args.project)
    if args.policy:
        snapshot = apply_policy(snapshot, load_policy(args.policy), source=str(args.policy))
    if args.host_bundle:
        snapshot = apply_host_bundles(snapshot, args.host_bundle)
    if args.robot:
        raw = ReadOnlyRobotCollector().fetch() if args.robot == "live" else load_robot_file(Path(args.robot))
        snapshot = apply_robot(snapshot, raw)
    if args.object_storage:
        raw_buckets = (
            ReadOnlyObjectStorageCollector().fetch() if args.object_storage == "live" else load_object_storage_file(Path(args.object_storage))
        )
        snapshot = apply_object_storage(snapshot, raw_buckets)
    if args.k8s:
        snapshot = apply_k8s(snapshot, load_k8s(args.k8s), args.k8s_cluster)
    if args.terraform:
        snapshot = apply_terraform(snapshot, args.terraform)
    if args.attestations:
        snapshot = apply_attestations(snapshot, load_attestations(args.attestations), args.attestations.name)
    if args.node_metrics:
        snapshot = apply_node_metrics(snapshot, load_node_metrics(args.node_metrics))
    return snapshot


def _filter_command(snapshot: Snapshot, command: str) -> Snapshot:
    if command in {"audit", "inventory", "coverage", "snapshot", "cost", "path", "explain", "ask", "map"}:
        return snapshot
    wanted = {
        "network": {"server", "network", "firewall", "service", "postgres", "redis"},
        "postgres": {"postgres", "server", "network", "firewall", "container"},
        "docker": {"container", "server", "network", "firewall", "service"},
    }[command]
    selected = {asset.id for asset in snapshot.assets if asset.type in wanted}
    return Snapshot(
        assets=[asset for asset in snapshot.assets if asset.id in selected],
        edges=[edge for edge in snapshot.edges if (edge.source in selected or edge.source == "internet") and edge.target in selected],
        facts=[fact for fact in snapshot.facts if fact.asset_id in selected],
        expectations=snapshot.expectations,
        signals=snapshot.signals,
        metadata=snapshot.metadata,
    )


def _render_map_svg(snapshot: Snapshot, topology: dict[str, Any], args: argparse.Namespace) -> str:
    titles = {
        "architecture": "Hetzner Cloud architecture",
        "connectivity": "Per-VM connectivity",
        "cost": "Per-VM monthly cost",
        "host": "Per-VM host layers",
        "posture": "Security posture",
    }
    title = args.title if args.title != "Hetzner Cloud architecture" else titles[args.view]
    cost = analyze_cost(snapshot) if any(asset.type == "pricing" for asset in snapshot.assets) else None
    findings = _findings(snapshot)
    actions = build_actions(snapshot, findings, cost)
    view_category = {"connectivity": "security", "cost": "cost", "host": "security"}.get(args.view)
    if view_category:
        actions = [item for item in actions if item.get("category") == view_category]
    if args.view == "host":
        host_rules = ("HETZ-DKR-", "HETZ-SSH-", "HETZ-HOST-", "HETZ-PG-", "HETZ-RDS-", "HETZ-NET-", "HETZ-K8S-")
        actions = [item for item in actions if any(rule.startswith(host_rules) for rule in item.get("rules", []))]
    actions = actions[: max(args.max_actions, 0)]
    if args.view == "connectivity":
        return render_connectivity_svg(topology, title, args.theme, actions)
    if args.view == "posture":
        from ..actions import coverage as coverage_rows
        from ..actions import provenance

        sources = next((line.removeprefix("Evidence sources: ").rstrip(".").split("; ")
                        for line in provenance(snapshot, cost) if line.startswith("Evidence sources:")), [])
        return render_posture_svg(posture_matrix(findings), coverage_rows(snapshot, cost), sources,
                                  title, args.theme, actions, other_sources(snapshot))
    if args.view == "host":
        hosts = _host_view_rows(snapshot)
        missing = sum(1 for asset in snapshot.assets if asset.type == "server") - len(hosts)
        return render_host_svg(hosts, title, args.theme, actions, missing)
    if args.view == "cost":
        return render_cost_svg(topology, cost or analyze_cost(snapshot), title, args.theme, actions)
    return render_svg(topology, title, args.theme, actions)


def _host_view_rows(snapshot: Snapshot) -> list[dict[str, Any]]:
    """Host-layer rows plus each server's containers, for the host view."""
    rows = host_rows(snapshot)
    by_name = {asset.name: asset for asset in snapshot.assets if asset.type == "server"}
    for row in rows:
        server = by_name[row["name"]]
        evidence = server.properties.get("host_evidence") or {}
        sshd = server.properties.get("sshd") or {}
        ssh = "ssh password login ON" if sshd.get("passwordauthentication") == "yes" else "ssh keys only" if sshd else "sshd not seen"
        row["subtitle"] = " · ".join(filter(None, [evidence.get("os"), ssh, f"bundle {evidence.get('collected_at') or ''}".strip()]))
        containers = []
        for asset in snapshot.assets:
            if asset.type != "container" or asset.properties.get("server") != server.id:
                continue
            props = asset.properties
            published = props.get("published") or []
            risks = [label for key, label in (("privileged", "privileged"), ("docker_socket", "docker.sock"), ("host_pid", "host PID"),
                                              ("host_network", "host network")) if props.get(key)]
            risks += [f"mount {path}" for path in props.get("sensitive_mounts") or []][:1]
            bypass = [item["host_port"] for item in published if item.get("bind") in {"wildcard", "public"} and item["host_port"] in row["docker_bypass"]]
            ports = ", ".join(sorted({f"{item['host_port']} on {'all interfaces' if item.get('bind') == 'wildcard' else item.get('bind')}" for item in published}))
            containers.append({"name": asset.name, "risks": ", ".join(risks), "ports": ports, "bypass": bool(bypass)})
        row["containers"] = sorted(containers, key=lambda item: (not item["risks"], not item["bypass"], item["name"]))
    return rows


def _findings_and_suppressed(snapshot: Snapshot, *, verify: bool = True) -> tuple[list[Finding], list[dict[str, Any]]]:
    candidates = hunt(snapshot)
    findings = verify_all(candidates, snapshot) if verify else candidates
    return apply_suppressions(findings, snapshot)


def _findings(snapshot: Snapshot, *, verify: bool = True) -> list[Finding]:
    return _findings_and_suppressed(snapshot, verify=verify)[0]


def run(args: argparse.Namespace) -> int:
    if args.command == "doctor":
        result = run_doctor(report_dir=args.report_dir)
        _write(json.dumps(result, indent=2) if args.format == "json" else render_doctor_markdown(result), args.output)
        return 1 if result["status"] == "fail" else 0
    if args.command == "checklist":
        _write(json.dumps(attestation_template(), indent=2) if args.template else render_checklist_markdown(), args.output)
        return 0
    if args.command == "metrics":
        if args.example:
            _write(json.dumps(NODE_METRICS_EXAMPLE, indent=2), args.output)
        elif args.queries or not args.prometheus:
            _write("\n".join(f"{key}: {query.replace('{days}', str(args.days))}" for key, query in QUERIES.items()), args.output)
        else:
            _write(json.dumps(collect_prometheus(args.prometheus, args.days), indent=2), args.output)
        return 0
    if args.command == "host-bundle":
        if args.parse:
            parsed = parse_bundle(args.parse.read_text(encoding="utf-8", errors="replace"))
            _write(json.dumps(parsed, indent=2, default=str), args.output)
        else:
            _write(BUNDLE_SCRIPT, args.output)
        return 0
    if args.command == "merge":
        _write(json.dumps(merge_snapshots(args.snapshots).to_dict(), indent=2), args.output)
        return 0
    if args.command == "diff":
        diff = diff_snapshots(load_snapshot(args.before), load_snapshot(args.after))
        output = json.dumps(diff, indent=2) if args.format == "json" else render_diff_markdown(diff)
        _write(output, args.output)
        return 1 if args.fail_on_regression and diff["security_regression"] else 0

    snapshot = _filter_command(_snapshot(args), args.command)
    if args.command == "inventory":
        output = json.dumps({"metadata": snapshot.metadata, "assets": [asset.to_dict() for asset in snapshot.assets]}, indent=2)
    elif args.command == "snapshot":
        output = json.dumps(snapshot.to_dict(), indent=2)
    elif args.command == "coverage":
        findings = _findings(snapshot, verify=args.verify)
        units = plan_coverage(snapshot)
        update_coverage(units, findings)
        output = render_coverage(units)
    elif args.command == "cost":
        report = analyze_cost(snapshot)
        output = json.dumps(report, indent=2) if args.format == "json" else render_cost_markdown(report)
    elif args.command == "path":
        result = AttackGraph(snapshot).explain_path(args.path_source, args.path_target, protocol=args.protocol, port=args.port, max_depth=args.max_depth)
        output = json.dumps(result, indent=2) if args.format == "json" else render_path_markdown(
            result, {asset.id: asset.name for asset in snapshot.assets if asset.name}
        )
    elif args.command == "explain":
        finding = next((item for item in _findings(snapshot) if item.id == args.finding_id), None)
        if finding is None:
            raise ValueError(f"finding not found: {args.finding_id}")
        output = json.dumps(finding.to_dict(), indent=2) if args.format == "json" else _explain_markdown(finding)
    elif args.command == "map":
        topology = build_topology(snapshot)
        output = {
            "json": lambda: json.dumps(topology, indent=2),
            "mermaid": lambda: render_mermaid(topology),
            "svg": lambda: _render_map_svg(snapshot, topology, args),
            "markdown": lambda: render_topology_markdown(topology),
        }[args.format]()
    elif args.command == "ask":
        answer = _answer(snapshot, args.question)
        output = json.dumps(answer, indent=2) if args.format == "json" else _answer_markdown(answer)
    else:
        findings, suppressed = _findings_and_suppressed(snapshot, verify=args.verify)
        minimum = SEVERITY_ORDER[args.severity]
        findings = [finding for finding in findings if finding.severity is None or SEVERITY_ORDER[finding.severity.value] <= minimum]
        if args.coverage_ledger:
            units = plan_coverage(snapshot)
            update_coverage(units, findings)
            save_coverage(args.coverage_ledger, units, prior_path=args.coverage_ledger)
        if args.format == "markdown":
            output = render_markdown(
                findings,
                snapshot.metadata,
                {asset.id: asset.name for asset in snapshot.assets if asset.name},
                build_summary(snapshot, findings, suppressed) if args.command == "audit" else None,
            )
        else:
            renderer = {"json": render_json, "sarif": render_sarif}[args.format]
            output = renderer(findings)
    _write(output, args.output)
    if getattr(args, "fail_on", "none") != "none" and args.command not in {"snapshot", "inventory"}:
        confirmed = [item for item in findings if item.status == FindingStatus.CONFIRMED]
        if args.fail_on == "confirmed-high":
            confirmed = [item for item in confirmed if item.severity and item.severity.value in {"critical", "high"}]
        if confirmed:
            print(f"hetzner-audit: {len(confirmed)} confirmed finding(s) match --fail-on {args.fail_on}", file=sys.stderr)
            return 1
    return 0


def _write(output: str, path: Path | None) -> None:
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output + ("" if output.endswith("\n") else "\n"), encoding="utf-8")
    else:
        print(output)


def _explain_markdown(finding: Finding) -> str:
    lines = [f"# {finding.id}", "", f"**{finding.status.value.upper()} · {finding.rule_id} · {md(finding.title)}**", "", f"Why: {md(finding.observation)}", "", "## Evidence chain", ""]
    for evidence in finding.evidence:
        lines.append(f"- ✓ `{md(evidence.kind)}` · `{md(evidence.asset_id)}` · `{md(evidence.path or 'normalized evidence')}`")
    lines.extend(["", "## Attack path", "", " → ".join(f"`{md(item)}`" for item in finding.attack_path), "", "## Verification challenge", "", md(finding.verification.notes), "", "## Remediation", "", md(finding.remediation)])
    return "\n".join(lines)


def _answer(snapshot: Snapshot, question: str) -> dict[str, Any]:
    lowered = question.lower()
    graph = AttackGraph(snapshot)
    paths = []
    if "internet" in lowered and any(word in lowered for word in ("database", "postgres", "redis", "db")):
        targets = [asset for asset in snapshot.assets if asset.type in {"postgres", "redis"} or asset.labels.get("role", "").lower() in {"db", "database", "postgres", "redis"} or any(token in asset.name.lower() for token in ("postgres", "redis", "-db"))]
        for target in targets:
            target_text = (target.type + target.labels.get("role", "") + target.name).lower()
            target_port = 6379 if "redis" in target_text else 5432
            result = graph.explain_path("internet", target.id, protocol="tcp", port=target_port)
            if result["path"]:
                paths.append(result)
    elif "staging" in lowered and "production" in lowered:
        sources = [
            asset
            for asset in snapshot.assets
            if asset.type in {"server", "container", "service"}
            and asset.labels.get("environment") in {"stage", "staging", "dev"}
        ]
        targets = [
            asset
            for asset in snapshot.assets
            if asset.type in {"server", "container", "service", "postgres", "redis"}
            and asset.labels.get("environment") in {"prod", "production"}
            and (
                asset.type in {"postgres", "redis"}
                or any(
                    token
                    in (
                        asset.labels.get("role", "")
                        + str(asset.properties.get("service", ""))
                        + asset.name
                    ).lower()
                    for token in ("db", "database", "postgres", "redis")
                )
            )
        ]
        for source in sources:
            for target in targets:
                target_text = (
                    target.type
                    + target.labels.get("role", "")
                    + str(target.properties.get("service", ""))
                    + target.name
                ).lower()
                target_port = 6379 if "redis" in target_text else 5432
                result = graph.explain_path(
                    source.id, target.id, protocol="tcp", port=target_port
                )
                if result["path"]:
                    paths.append(result)
    else:
        return {"question": question, "result": "unsupported_question", "answer": "Use a question about Internet-to-database or staging-to-production reachability.", "coverage": _coverage_summary(snapshot), "paths": []}
    # Internet questions are about direct exposure; multi-hop pivots are reported separately.
    # A hop through a load balancer is forwarding, not a pivot: only other intermediate hosts make a path indirect.
    asset_types = {asset.id: asset.type for asset in snapshot.assets}
    indirect = [
        path
        for path in paths
        if path["source"] == "internet"
        and any(asset_types.get(node) != "load_balancer" for node in path["path"][1:-1])
    ]
    paths = [path for path in paths if path not in indirect]
    confirmed = [path for path in paths if path["result"] == "reachable"]
    possible = [path for path in paths if path["result"] == "cloud_path_present"]
    if paths:
        answer = f"{len(confirmed)} complete and {len(possible)} cloud-only path(s) observed."
    elif indirect:
        answer = "No direct path was observed; host and runtime controls are not evidenced."
    else:
        answer = "No matching path was observed; collection gaps can prevent a negative proof."
    if indirect:
        answer += f" {len(indirect)} indirect path(s) require compromising a publicly reachable host first."
    return {
        "question": question,
        "result": "reachable" if confirmed else "needs_validation" if possible else "no_confirmed_path",
        "answer": answer,
        "coverage": _coverage_summary(snapshot),
        "paths": paths,
        "indirect_paths": indirect,
    }


def _coverage_summary(snapshot: Snapshot) -> dict[str, Any]:
    by_type: dict[str, int] = {}
    for asset in snapshot.assets:
        by_type[asset.type] = by_type.get(asset.type, 0) + 1
    failed = [name for name, state in snapshot.metadata.get("coverage", {}).items() if isinstance(state, dict) and state.get("status") not in {"collected", None}]
    return {"assets_checked": by_type, "collector_gaps": failed}


def _answer_markdown(answer: dict[str, Any]) -> str:
    lines = ["# Infrastructure question", "", f"**Question:** {answer['question']}", "", f"**Result:** `{answer['result']}`", "", answer["answer"], "", "## Checked", ""]
    for kind, count in sorted(answer["coverage"]["assets_checked"].items()):
        lines.append(f"- {kind}: {count}")
    if answer["coverage"]["collector_gaps"]:
        lines.extend(["", "## Missing evidence", ""])
        lines.extend(f"- {item}" for item in answer["coverage"]["collector_gaps"])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> None:
    try:
        raise SystemExit(run(build_parser().parse_args(argv)))
    except (HCloudCollectionError, RobotCollectionError, ObjectStorageError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
