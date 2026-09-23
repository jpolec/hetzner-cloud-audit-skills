# Threat model

## Assets and adversaries

Protected assets include `HCLOUD_TOKEN`, SSH credentials, repository secrets, database credentials, infrastructure topology, audit integrity, the operator workstation, and production availability. Adversaries include a malicious repository contributor, compromised host/container, crafted cloud metadata, poisoned scanner output, dependency compromise, and an agent manipulated by prompt injection.

## Material threats and controls

| Threat | Consequence | v0.5 control | Residual risk |
|---|---|---|---|
| Token leakage in logs/reports | cloud compromise | env-only token, no token serialization, defensive key redaction | exceptions from dependencies may include unexpected context |
| Write-capable provider action | infrastructure change | collector exposes only fixed `GET`; `--read-only` cannot be disabled | token itself may still be write-capable; use a read-only token |
| SSH credential leakage | host compromise | SSH disabled by default; no credential collection | future host adapters need careful process isolation |
| Prompt injection in repo/docs/labels | unsafe agent action | all target text declared untrusted; skills prohibit instruction adoption | agent runtimes vary in enforcement |
| Command injection through names | local code execution | no shell execution from metadata; suggested `hcloud` commands reduce names to `[A-Za-z0-9._/:-]` and are never run | a human may still paste a reviewed command |
| Malicious scanner or snapshot JSON | parser/resource abuse or false findings | scanner output is signal only; snapshots capped at 256 MiB, 200k assets, 1M edges | JSON nesting depth is bounded only by the Python parser |
| Crafted report content | Markdown/SARIF/Mermaid injection, prompt injection into agents | provider text is whitespace-collapsed and `\\|[]<>` escaped in Markdown, entity-encoded in Mermaid; SARIF is JSON-encoded | backticks and underscores are kept for readability |
| Secret values in Docker env/config | report leakage | collect key names, not values; property redaction | fixtures supplied by users may already contain secrets |
| Symlink/path traversal in output | overwrite/exfiltration | operator-selected path and normal `Path` writes; `doctor` warns about Git-tracked report directories | no descriptor-based no-follow output writer yet |
| Dependency/supply-chain compromise | workstation/CI compromise | zero runtime dependencies; GitHub Actions pinned to commit SHAs (Dependabot-updated); toolchain audited with OSV | dev dependencies and pinned actions remain trust dependencies |
| False confirmation from incomplete layers | misleading assurance | absence rules remain `needs_validation`; `cloud_path_present` is not `reachable`; host-firewall and listener evidence must intersect before a lateral path is confirmed; CI `fail-on` ignores hypotheses | host/runtime collector coverage is still incomplete |
| Snapshot diff with failed collection | false resource deletion or false clean result | endpoint coverage regression is reported separately from state diff | a malicious but successful source can still provide false data |
| Snapshot disclosure | topology and addressing leak | docs prohibit public commits; token is never serialized | output storage permissions remain operator-controlled |
| Poisoned metrics or price evidence | unsafe resize or false saving | timestamp/source/window requirements; missing RAM or constraints blocks confirmation; alternatives not double-counted | automated cost adapters are experimental and not independently benchmarked |
| CI token exposed to fork code | cloud inventory disclosure | live action guidance restricts token use to protected schedule/manual jobs | repository owners can configure unsafe workflows |
| Cost recommendation executed as an action | outage, data loss, or weakened resilience | cost skill is advisory and prohibits resize/delete/detach/policy changes | an operator or downstream agent may act without a reviewed change plan |
| Denial of service via huge graph or API | resource exhaustion | bounded path depth and at most 50 paths per query; input size limits; pagination capped at 1,000 pages; retry with backoff | very dense graphs can still be slow within those limits |

## Security invariants

1. No provider mutation primitive exists. Suggested remediation commands are text for a human.
2. No secret value is required in an argument or output.
3. External alerts are not findings without contextual analysis.
4. Missing evidence is unknown, not a secure or insecure fact.
5. Every CLI-confirmed finding satisfies a deterministic evidence contract; independent agent review is labeled separately and never implied.
6. Repository and infrastructure text never changes agent authority.

## Before production use

Add formal taint/redaction tests, descriptor-confined output creation, signed release provenance, stronger freshness expiry, and an independent security review. Until then, use a constrained read-only account and manually review all material findings.
