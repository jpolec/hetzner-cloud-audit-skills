# Architecture

## Collect → reason → verify

```text
Hetzner API     owner policy     repo/IaC     host/runtime*     scanners*
     └──────────── temporal facts + normalized evidence ───────────────┘
                                      │
                    typed evidence and attack graph
                                      │
            path queries + temporal diff + candidate rules
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
- `Fact`: stable identity, value, observation time, run ID, collector version, source path, and optional freshness budget.
- `Evidence`: source, kind, asset identity, observed value, optional source path and timestamp.
- `Edge`: directed relation with optional protocol/port and supporting evidence.
- `Finding`: observation, expected/actual state, path, prerequisites, impact, severity, confidence, verifier record, and remediation.
- `CoverageUnit`: stable asset/layer/attack-class identity and current/prior result fingerprints.
- `ArchitectureRecommendation`: independently reviewed cost/security/reliability decision with timestamped metrics, price basis, risk, confidence, and rollback criteria.

The attack graph is an in-memory adjacency list with bounded simple-path traversal; a graph database is unnecessary at current project sizes. Every hop is typed (FILTER: a firewall admits the source; FORWARD: a load balancer or node port; ROUTE: a network delivers to a member; PIVOT: the attacker must compromise the hop's source first; RUNTIME: a listener or published port), and `path` reports whether the target is reachable directly or only after pivots. The source of a query is taken as already controlled, so leaving it is not a pivot; among candidate paths the one needing the fewest pivots wins, then the shortest. A path whose every layer is evidenced but which needs a pivot is `reachable_after_pivot`, not `reachable`. `reachable`, `cloud_path_present`, and `unknown` remain distinct so provider reachability is not mistaken for an observed application path.

Snapshots serialize assets, edges, facts, expectations, signals, endpoint coverage, and run identity. `diff` reports two kinds of drift:

- **Structural drift:** fact identities, edge identities, and assets, with coverage regressions kept separate from removals.
- **Security drift:** the exact allowed-flow difference. Ingress and egress are sets of rectangles (source or destination address interval × port interval) per address family and protocol; `after − before` is computed exactly by sweeping the source axis (slabs of source addresses with one port set each, linear in the number of rules) and classified afterwards (world, wide, edge provider, allow-list). `--regression-policy broad` fails on new world or wide exposure; `strict` on any growth, including a wider allow-list, a different trusted source, or new egress.

Cost drift is reported as a catalog delta split into the effect of resource changes (both snapshots priced at the earlier catalog) and provider price changes; it is not invoice-verified.

## Trust boundaries

Control-plane tokens, SSH credentials, repositories, API metadata, external scanner output, and generated reports cross distinct boundaries. Tokens are read only from environment variables and never serialized. Repository prose, labels, names, and scanner fields are data, never instructions. Reports receive sanitized resource properties and should be treated as sensitive.

## Extension points

Collectors return a `Snapshot`; integrations return neutral `signals`; rules are functions from `(Snapshot, AttackGraph)` to candidates; reporters consume verified findings. Future providers and services can implement those contracts without changing the verdict model.

Cost analysis uses the same normalized boundary but a separate recommendation schema. The headline total selects at most one candidate per asset and separates potential from confirmed savings. Provider adapters own product catalogs, billing semantics, and metric availability. See [cost and multi-cloud architecture](finops-architecture.md).

## MCP decision

Deferred. A read-only MCP facade could expose asset lists, topology, findings, and evidence, but the project first needs stable authorization, pagination, evidence freshness, and output contracts. The CLI and SKILL packages already serve humans, CI, and agents without an always-on server.

## Reachability semantics

A path in the attack graph is a pivot chain: each hop is its own flow, so an attacker may enter host A on one port and then reach host B on another. Only the final hop is filtered by the requested protocol and port. Load-balancer hops are forwarding, not pivots: the LB's listen port and the target's destination port are separate edges, and `ask` treats such paths as direct exposure. Internet exposure itself is computed separately in `flows.py` as sets of allowed flows per asset, keyed by (address family, protocol, source class). The snapshot diff compares those sets, so a range that widens counts as a regression, and a new public IP behind a deny-all firewall does not.


## Evidence beyond the Cloud API (v0.7)

Optional sources feed the same snapshot, facts, and rules:

| Source | Module | Enters the snapshot as |
|---|---|---|
| Host bundle (owner-run script) | `host/` | server properties (host firewall per family, listeners, Docker publications, sshd), `container`/`postgres`/`redis` assets, `runs` edges (never traversed), Internet and private-network edges only where every layer admits the port |
| Terraform JSON | `iac.py` | `metadata.terraform` and network-access expectations |
| Provider `/actions` | `collectors/hcloud.py` | `signals` of type `provider_action` |
| Node exporter via Prometheus | `node_metrics.py` | `guest_metrics` on servers |
| Robot webservice | `collectors/robot.py` | `robot_server`, `vswitch`, `ssh_key` assets and edges |
| Object Storage (S3) | `collectors/objectstorage.py` | `bucket` assets with per-setting read status |
| kubectl listing | `k8s.py` | `k8s_*` assets, `k8s` on node servers, `publishes` edges for NodePorts |
| Owner checklist | `attestations.py` | `metadata.attestations` |
| Several projects | `projects.py` | merged snapshot, `project` on every asset |

Host firewalls (UFW, nftables, iptables) are normalized to ordered rules and evaluated by one first-match function per address family. A rule the parser does not fully model makes the answer `None` (unknown); unknown layers never produce `rejected` or `confirmed`.
