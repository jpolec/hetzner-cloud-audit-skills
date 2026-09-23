"""Safe local CLI for evidence-backed Hetzner infrastructure audits."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from ..analyzers import hunt
from ..collectors.fixture import load_snapshot
from ..collectors.hcloud import HCloudCollectionError, ReadOnlyHCloudCollector
from ..cost import analyze_cost, render_cost_markdown
from ..coverage import plan_coverage, render_coverage, save_coverage, update_coverage
from ..findings import render_json, render_markdown, render_sarif
from ..graph import AttackGraph, render_path_markdown
from ..models import Finding, Severity, Snapshot
from ..policy import apply_policy, load_policy
from ..temporal import diff_snapshots, render_diff_markdown
from ..topology import build_topology, render_mermaid, render_svg, render_topology_markdown
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hetzner-audit", description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("audit", "inventory", "network", "postgres", "docker", "coverage", "snapshot"):
        cmd = subparsers.add_parser(name)
        _common(cmd)
        cmd.add_argument("--severity", choices=tuple(SEVERITY_ORDER), default="info")
        cmd.add_argument("--verify", action=argparse.BooleanOptionalAction, default=True)
        cmd.add_argument("--coverage-ledger", type=Path)

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

    topology = subparsers.add_parser("map", help="Network map as Markdown/Mermaid, SVG, or JSON")
    _common(topology, formats=("markdown", "mermaid", "svg", "json"))
    topology.add_argument("--title", default="Hetzner network map")
    topology.add_argument("--theme", choices=("light", "dark"), default="light", help="SVG color theme")
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
            include_metrics=args.command == "cost",
            metrics_days=getattr(args, "metrics_days", 30),
        ).collect()
    if args.policy:
        snapshot = apply_policy(snapshot, load_policy(args.policy), source=str(args.policy))
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


def _findings(snapshot: Snapshot, *, verify: bool = True) -> list[Finding]:
    candidates = hunt(snapshot)
    return verify_all(candidates, snapshot) if verify else candidates


def run(args: argparse.Namespace) -> int:
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
            "svg": lambda: render_svg(topology, args.title, args.theme),
            "markdown": lambda: render_topology_markdown(topology),
        }[args.format]()
    elif args.command == "ask":
        answer = _answer(snapshot, args.question)
        output = json.dumps(answer, indent=2) if args.format == "json" else _answer_markdown(answer)
    else:
        findings = _findings(snapshot, verify=args.verify)
        minimum = SEVERITY_ORDER[args.severity]
        findings = [finding for finding in findings if finding.severity is None or SEVERITY_ORDER[finding.severity.value] <= minimum]
        if args.coverage_ledger:
            units = plan_coverage(snapshot)
            update_coverage(units, findings)
            save_coverage(args.coverage_ledger, units, prior_path=args.coverage_ledger)
        if args.format == "markdown":
            output = render_markdown(
                findings, snapshot.metadata, {asset.id: asset.name for asset in snapshot.assets if asset.name}
            )
        else:
            renderer = {"json": render_json, "sarif": render_sarif}[args.format]
            output = renderer(findings)
    _write(output, args.output)
    return 0


def _write(output: str, path: Path | None) -> None:
    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output + ("" if output.endswith("\n") else "\n"), encoding="utf-8")
    else:
        print(output)


def _explain_markdown(finding: Finding) -> str:
    lines = [f"# {finding.id}", "", f"**{finding.status.value.upper()} · {finding.rule_id} · {finding.title}**", "", f"Why: {finding.observation}", "", "## Evidence chain", ""]
    for evidence in finding.evidence:
        lines.append(f"- ✓ `{evidence.kind}` · `{evidence.asset_id}` · `{evidence.path or 'normalized evidence'}`")
    lines.extend(["", "## Attack path", "", " → ".join(f"`{item}`" for item in finding.attack_path), "", "## Verification challenge", "", finding.verification.notes, "", "## Remediation", "", finding.remediation])
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
    indirect = [path for path in paths if path["source"] == "internet" and len(path["path"]) > 1]
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
    except (HCloudCollectionError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
