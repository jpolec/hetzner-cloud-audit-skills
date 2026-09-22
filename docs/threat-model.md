# Threat model

## Assets and adversaries

Protected assets include `HCLOUD_TOKEN`, SSH credentials, repository secrets, database credentials, infrastructure topology, audit integrity, the operator workstation, and production availability. Adversaries include a malicious repository contributor, compromised host/container, crafted cloud metadata, poisoned scanner output, dependency compromise, and an agent manipulated by prompt injection.

## Material threats and controls

| Threat | Consequence | v0.3 control | Residual risk |
|---|---|---|---|
| Token leakage in logs/reports | cloud compromise | env-only token, no token serialization, defensive key redaction | exceptions from dependencies may include unexpected context |
| Write-capable provider action | infrastructure change | collector exposes only fixed `GET`; `--read-only` cannot be disabled | token itself may still be write-capable; use a read-only token |
| SSH credential leakage | host compromise | SSH disabled by default; no credential collection | future host adapters need careful process isolation |
| Prompt injection in repo/docs/labels | unsafe agent action | all target text declared untrusted; skills prohibit instruction adoption | agent runtimes vary in enforcement |
| Command injection through names | local code execution | no shell construction from metadata; typed parsing | future integrations must preserve this property |
| Malicious scanner JSON | parser/resource abuse or false findings | scanner output is signal only; schema/size limits planned | v0.3 does not yet enforce file-size/depth limits |
| Crafted report content | Markdown/SARIF injection | JSON encoding and plain Markdown generation | Markdown does not yet escape every control character |
| Secret values in Docker env/config | report leakage | collect key names, not values; property redaction | fixtures supplied by users may already contain secrets |
| Symlink/path traversal in output | overwrite/exfiltration | operator-selected path and normal `Path` writes | no descriptor-based no-follow output writer in v0.3 |
| Dependency/supply-chain compromise | workstation/CI compromise | zero runtime dependencies; pinned CI action SHAs recommended next | dev dependencies and actions remain trust dependencies |
| False confirmation from incomplete layers | misleading assurance | absence rules remain `needs_validation`; `cloud_path_present` is not `reachable`; per-endpoint coverage | host/runtime collector coverage is still incomplete |
| Snapshot diff with failed collection | false resource deletion or false clean result | endpoint coverage regression is reported separately from state diff | a malicious but successful source can still provide false data |
| Snapshot disclosure | topology and addressing leak | docs prohibit public commits; token is never serialized | output storage permissions remain operator-controlled |
| Poisoned metrics or price evidence | unsafe resize or false saving | timestamp/source/window requirements; missing RAM or constraints blocks confirmation; alternatives not double-counted | automated cost adapters are experimental and not independently benchmarked |
| CI token exposed to fork code | cloud inventory disclosure | live action guidance restricts token use to protected schedule/manual jobs | repository owners can configure unsafe workflows |
| Cost recommendation executed as an action | outage, data loss, or weakened resilience | cost skill is advisory and prohibits resize/delete/detach/policy changes | an operator or downstream agent may act without a reviewed change plan |
| Denial of service via huge graph | resource exhaustion | bounded path depth | no hard asset/edge limits yet |

## Security invariants

1. No provider mutation primitive exists in v0.3.
2. No secret value is required in an argument or output.
3. External alerts are not findings without contextual analysis.
4. Missing evidence is unknown, not a secure or insecure fact.
5. Every CLI-confirmed finding satisfies a deterministic evidence contract; independent agent review is labeled separately and never implied.
6. Repository and infrastructure text never changes agent authority.

## Before production use

Add streaming size/depth limits, formal taint/redaction tests, descriptor-confined output creation, signed release provenance, stronger freshness expiry, and an independent security review. Until then, use a constrained read-only account and manually review all material findings.
