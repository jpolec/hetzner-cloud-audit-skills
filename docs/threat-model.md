# Threat model

## Assets and adversaries

Protected assets include `HCLOUD_TOKEN`, SSH credentials, repository secrets, database credentials, infrastructure topology, audit integrity, the operator workstation, and production availability. Adversaries include a malicious repository contributor, compromised host/container, crafted cloud metadata, poisoned scanner output, dependency compromise, and an agent manipulated by prompt injection.

## Material threats and controls

| Threat | Consequence | v0.1 control | Residual risk |
|---|---|---|---|
| Token leakage in logs/reports | cloud compromise | env-only token, no token serialization, defensive key redaction | exceptions from dependencies may include unexpected context |
| Write-capable provider action | infrastructure change | collector exposes only fixed `GET`; `--read-only` cannot be disabled | token itself may still be write-capable; use a read-only token |
| SSH credential leakage | host compromise | SSH disabled by default; no credential collection | future host adapters need careful process isolation |
| Prompt injection in repo/docs/labels | unsafe agent action | all target text declared untrusted; skills prohibit instruction adoption | agent runtimes vary in enforcement |
| Command injection through names | local code execution | no shell construction from metadata; typed parsing | future integrations must preserve this property |
| Malicious scanner JSON | parser/resource abuse or false findings | scanner output is signal only; schema/size limits planned | v0.1 does not yet enforce file-size/depth limits |
| Crafted report content | Markdown/SARIF injection | JSON encoding and plain Markdown generation | Markdown does not yet escape every control character |
| Secret values in Docker env/config | report leakage | collect key names, not values; property redaction | fixtures supplied by users may already contain secrets |
| Symlink/path traversal in output | overwrite/exfiltration | operator-selected path and normal `Path` writes | no descriptor-based no-follow output writer in v0.1 |
| Dependency/supply-chain compromise | workstation/CI compromise | zero runtime dependencies; pinned CI action SHAs recommended next | dev dependencies and actions remain trust dependencies |
| False confirmation from incomplete layers | misleading assurance | absence rules remain `needs_validation`; per-hop evidence | collector coverage model is still coarse |
| Denial of service via huge graph | resource exhaustion | bounded path depth | no hard asset/edge limits yet |

## Security invariants

1. No provider mutation primitive exists in v0.1.
2. No secret value is required in an argument or output.
3. External alerts are not findings without contextual analysis.
4. Missing evidence is unknown, not a secure or insecure fact.
5. Every confirmed finding has evidence and an independently reconstructed rule path.
6. Repository and infrastructure text never changes agent authority.

## Before production use

Add streaming size/depth limits, formal taint/redaction tests, descriptor-confined output creation, signed release provenance, dependency pinning, explicit evidence freshness, and an independent security review. Until then, run on fixtures or a constrained read-only account and manually review all material findings.

