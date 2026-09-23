# Validation corpus (real projects, anonymized)

The fixture and generated benchmarks prove that rules match their own specification. They do not
measure how often the audit is wrong on real infrastructure. This corpus does.

## What we measure

| Metric | Meaning | Target |
|---|---|---|
| **False-confirmed rate** | P(finding is false \| verdict = confirmed) | ≈ 0 |
| Needs-validation precision | share of hypotheses that turn out true | reported, no target |
| False negatives | issues the owner knows about that the audit missed | as low as possible |
| Collector failure rate | failed or partial sources per project | reported |
| Host parser unknown rate | host bundles whose firewall could not be read | reported |

## How to contribute a project

1. Snapshot your project with a read-only token (optionally with `--host-bundle`, `--robot`, …):
   `hetzner-audit snapshot --output snapshot.json`
2. Anonymize it: `hetzner-audit anonymize snapshot.json --output benchmarks/corpus/<name>/snapshot.json`.
   Names, label values, public addresses, provider IDs, unusual ports, domains, and free text are replaced
   consistently; the findings stay the same. **Review the file before sharing it.**
3. Create the labels template: `uv run python scripts/corpus_eval.py --template benchmarks/corpus/<name>`.
4. For every finding set `truth` to `true` or `false`, and add issues the audit missed to `missing`
   (`{"rule_id": "...", "asset": "...", "note": "..."}`).
5. Open a pull request, or send the two files privately if you prefer.

Score the whole corpus with `uv run python scripts/corpus_eval.py benchmarks/corpus`.

We are looking for variety: small, medium, and large projects; Docker, Kubernetes, and plain VMs;
Cloud-only and Robot hybrids; with and without an edge proxy.

## Status

The corpus is empty in the repository today. The maintainer's own project is scored locally and not
published. Until several independent projects are here, treat every fixture-tested rule as
unvalidated on real infrastructure (reports say so next to each finding).
