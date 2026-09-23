"""Score the audit against owner-labeled real projects (the validation corpus).

Layout: benchmarks/corpus/<project>/snapshot.json (anonymized with `hetzner-audit anonymize`)
and labels.json. Create a labels template to fill in:

    uv run python scripts/corpus_eval.py --template benchmarks/corpus/<project>

Then score every project:

    uv run python scripts/corpus_eval.py benchmarks/corpus

The headline metric is the false-confirmed rate, P(finding is false | verdict = confirmed): for an
auditor it should be close to zero. See benchmarks/corpus/README.md for the label format.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hetzner_security.analyzers import hunt  # noqa: E402
from hetzner_security.collectors.fixture import load_snapshot  # noqa: E402
from hetzner_security.verification import verify_all  # noqa: E402


def _findings(project: Path) -> list[Any]:
    snapshot = load_snapshot(project / "snapshot.json")
    return verify_all(hunt(snapshot), snapshot), snapshot  # type: ignore[return-value]


def template(project: Path) -> None:
    findings, _snapshot = _findings(project)
    labels = [
        {"rule_id": item.rule_id, "asset": asset, "status": item.status.value, "title": item.title, "truth": "unknown"}
        for item in findings if item.status.value != "rejected" for asset in item.assets[:1]
    ]
    path = project / "labels.json"
    path.write_text(json.dumps({"labels": labels, "missing": [], "_help": "Set truth to true or false; add issues the tool "
                                "missed to 'missing' as {rule_id, asset, note}."}, indent=2) + "\n")
    print(f"wrote {path} with {len(labels)} findings to label")


def score(root: Path) -> dict[str, Any]:
    totals: Counter[str] = Counter()
    per_rule: dict[str, Counter[str]] = {}
    for project in sorted(path for path in root.iterdir() if (path / "snapshot.json").exists() and (path / "labels.json").exists()):
        findings, snapshot = _findings(project)
        labels = json.loads((project / "labels.json").read_text())
        truth = {(item["rule_id"], item["asset"]): item.get("truth") for item in labels.get("labels", [])}
        found = {(item.rule_id, asset) for item in findings if item.status.value != "rejected" for asset in item.assets}
        totals["projects"] += 1
        for item in findings:
            if item.status.value == "rejected":
                continue
            key = (item.rule_id, item.assets[0] if item.assets else "")
            label = truth.get(key)
            bucket = per_rule.setdefault(item.rule_id, Counter())
            verdict = item.status.value
            if label in (True, "true"):
                totals[f"{verdict}_true"] += 1
                bucket[f"{verdict}_true"] += 1
            elif label in (False, "false"):
                totals[f"{verdict}_false"] += 1
                bucket[f"{verdict}_false"] += 1
            else:
                totals["unlabeled"] += 1
        for miss in labels.get("missing", []):
            if (miss.get("rule_id"), miss.get("asset")) not in found:
                totals["false_negatives"] += 1
                per_rule.setdefault(str(miss.get("rule_id")), Counter())["false_negatives"] += 1
        coverage = snapshot.metadata.get("coverage") or {}
        totals["collector_sources"] += len(coverage)
        totals["collector_failed"] += sum(1 for state in coverage.values() if isinstance(state, dict) and state.get("status") in {"failed", "partial"})
        hosts = [asset for asset in snapshot.assets if asset.type == "server" and asset.properties.get("host_evidence")]
        totals["host_bundles"] += len(hosts)
        totals["host_unknown"] += sum(1 for asset in hosts if not (asset.properties.get("host_firewall") or {}).get("known", True))

    def rate(numerator: int, denominator: int) -> float | None:
        return round(numerator / denominator, 3) if denominator else None

    return {
        "projects": totals["projects"],
        "false_confirmed_rate": rate(totals["confirmed_false"], totals["confirmed_true"] + totals["confirmed_false"]),
        "needs_validation_precision": rate(totals["needs_validation_true"], totals["needs_validation_true"] + totals["needs_validation_false"]),
        "false_negatives": totals["false_negatives"],
        "unlabeled_findings": totals["unlabeled"],
        "collector_failure_rate": rate(totals["collector_failed"], totals["collector_sources"]),
        "host_parser_unknown_rate": rate(totals["host_unknown"], totals["host_bundles"]),
        "per_rule": {rule: dict(counts) for rule, counts in sorted(per_rule.items())},
    }


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--template":
        template(Path(sys.argv[2]))
        return 0
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "benchmarks/corpus")
    result = score(root)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
