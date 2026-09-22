"""Safe local CLI for humans, CI, and coding agents."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..analyzers import hunt
from ..collectors.fixture import load_snapshot
from ..collectors.hcloud import HCloudCollectionError, ReadOnlyHCloudCollector
from ..coverage import plan_coverage, render_coverage, save_coverage, update_coverage
from ..findings import render_json, render_markdown, render_sarif
from ..models import Severity, Snapshot
from ..verification import verify_all

SEVERITY_ORDER = {severity.value: index for index, severity in enumerate(Severity)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hetzner-audit", description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("audit", "inventory", "network", "postgres", "docker", "coverage"):
        cmd = subparsers.add_parser(name)
        cmd.add_argument("--input", type=Path, help="Normalized JSON snapshot; avoids live API access")
        cmd.add_argument("--format", choices=("json", "markdown", "sarif"), default="markdown")
        cmd.add_argument("--output", type=Path)
        cmd.add_argument("--severity", choices=tuple(SEVERITY_ORDER), default="info")
        cmd.add_argument("--verify", action=argparse.BooleanOptionalAction, default=True)
        cmd.add_argument("--read-only", action=argparse.BooleanOptionalAction, default=True)
        cmd.add_argument("--no-ssh", action="store_true", default=True)
        cmd.add_argument("--no-external-tools", action="store_true")
        cmd.add_argument("--dry-run", action="store_true")
        cmd.add_argument("--coverage-ledger", type=Path)
    return parser


def _snapshot(args: argparse.Namespace) -> Snapshot:
    if not args.read_only:
        raise ValueError("v0.2 supports read-only mode only")
    if args.input:
        return load_snapshot(args.input)
    if args.dry_run:
        return Snapshot(metadata={"dry_run": True, "planned_collector": "hcloud_api_get_only"})
    return ReadOnlyHCloudCollector().collect()


def _filter_command(snapshot: Snapshot, command: str) -> Snapshot:
    if command in {"audit", "inventory", "coverage"}:
        return snapshot
    wanted = {
        "network": {"server", "network", "firewall", "service", "postgres", "redis"},
        "postgres": {"postgres", "server", "network", "firewall", "container"},
        "docker": {"container", "server", "network", "firewall", "service"},
    }[command]
    selected = {asset.id for asset in snapshot.assets if asset.type in wanted}
    return Snapshot(
        assets=[asset for asset in snapshot.assets if asset.id in selected],
        edges=[edge for edge in snapshot.edges if edge.source in selected or edge.source == "internet" if edge.target in selected],
        expectations=snapshot.expectations,
        signals=snapshot.signals,
        metadata=snapshot.metadata,
    )


def run(args: argparse.Namespace) -> int:
    snapshot = _filter_command(_snapshot(args), args.command)
    if args.command == "inventory":
        output = json.dumps({"metadata": snapshot.metadata, "assets": [a.to_dict() for a in snapshot.assets]}, indent=2)
    elif args.command == "coverage":
        candidates = hunt(snapshot)
        findings = verify_all(candidates, snapshot) if args.verify else candidates
        units = plan_coverage(snapshot)
        update_coverage(units, findings)
        output = render_coverage(units)
    else:
        candidates = hunt(snapshot)
        findings = verify_all(candidates, snapshot) if args.verify else candidates
        minimum = SEVERITY_ORDER[args.severity]
        findings = [
            finding
            for finding in findings
            if finding.severity is None or SEVERITY_ORDER[finding.severity.value] <= minimum
        ]
        if args.coverage_ledger:
            units = plan_coverage(snapshot)
            update_coverage(units, findings)
            save_coverage(args.coverage_ledger, units, prior_path=args.coverage_ledger)
        renderer = {"json": render_json, "markdown": render_markdown, "sarif": render_sarif}[args.format]
        output = renderer(findings)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + ("" if output.endswith("\n") else "\n"), encoding="utf-8")
    else:
        print(output)
    return 0


def main(argv: list[str] | None = None) -> None:
    try:
        raise SystemExit(run(build_parser().parse_args(argv)))
    except (HCloudCollectionError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
