# Architecture

## Collect → reason → verify

```text
Hetzner API     repo/IaC     host/SSH*     Docker*     PG/Redis*     scanners*
     └─────────────── normalized assets, facts, evidence ───────────────┘
                                      │
                         typed directed attack graph
                                      │
                       coverage-led candidate rules
                                      │
                    root-cause fingerprint + dedupe
                                      │
                 independent verifier / deterministic verifier†
                                      │
                  JSON ───── Markdown ───── SARIF
```

`*` optional and explicitly enabled or operator-provided. `†` The deterministic verifier is component-separated but not an independent agent; see limitations.

Collectors do not assign severity. Analyzers generate candidates. The verifier can confirm, request a specific validation, or reject. Reporters cannot change verdicts.

## Data model

- `Asset`: provider, host, runtime, or service identity with untrusted properties and labels.
- `Evidence`: source, kind, asset identity, observed value, optional source path and timestamp.
- `Edge`: directed relation with optional protocol/port and supporting evidence.
- `Finding`: observation, expected/actual state, path, prerequisites, impact, severity, confidence, verifier record, and remediation.
- `CoverageUnit`: stable asset/layer/attack-class identity and current/prior result fingerprints.
- `ArchitectureRecommendation`: independently reviewed cost/security/reliability decision with timestamped metrics, price basis, risk, confidence, and rollback criteria.

The attack graph is an in-memory adjacency list with bounded simple-path traversal. A graph database is unnecessary for v0.2 fixtures and small-to-medium projects.

## Trust boundaries

Control-plane tokens, SSH credentials, repositories, API metadata, external scanner output, and generated reports cross distinct boundaries. Tokens are read only from environment variables and never serialized. Repository prose, labels, names, and scanner fields are data, never instructions. Reports receive sanitized resource properties and should be treated as sensitive.

## Extension points

Collectors return a `Snapshot`; integrations return neutral `signals`; rules are functions from `(Snapshot, AttackGraph)` to candidates; reporters consume verified findings. Future providers and services can implement those contracts without changing the verdict model.

Cost analysis uses the same normalized boundary but a separate recommendation schema. Provider adapters own product catalogs, billing semantics, and metric availability; shared reasoning must not contain Hetzner SKU names. See [cost and multi-cloud architecture](finops-architecture.md).

## MCP decision

Deferred. A read-only MCP facade could expose asset lists, topology, findings, and evidence, but the project first needs stable authorization, pagination, evidence freshness, and output contracts. The CLI and SKILL packages already serve humans, CI, and agents without an always-on server.
