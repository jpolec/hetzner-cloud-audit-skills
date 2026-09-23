# hetzner-cloud-audit-skills

**Audit your Hetzner Cloud with one read-only token. No SSH, no writes. Every finding cites its evidence.**

It answers three questions about a Hetzner project:

1. **What is reachable from the Internet?** Open databases, public SSH, servers without a firewall.
2. **What can cross a trust boundary?** For example, can a staging box reach the production database?
3. **What changed since the last run?** New public ports, removed firewalls, coverage gaps.

It also produces an experimental cost report covering idle servers, rightsizing and ARM candidates.

![Audit summary: confirmed findings, findings that need validation, and attack paths](docs/assets/demo-overview.png)

> Independent open-source project. Not affiliated with or endorsed by Hetzner or Cloudflare. v0.3 is alpha: review every high-impact result before acting on it.

## Why another scanner?

Most cloud scanners report "port 5432 is open in the firewall" and stop there. This tool separates what it **proved** from what it **suspects**:

| Result | Meaning |
|---|---|
| `confirmed` / `reachable` | Every link in the chain is evidenced: network, firewall, host rule, listener, service config |
| `needs_validation` / `cloud_path_present` | Hetzner topology allows it, but host or runtime evidence is missing |
| `unknown` | No path was seen, but coverage is too incomplete to claim isolation |

A missing collector is reported as a gap. It is never reported as "secure".

## Quick start

### Choose how you want to run it

| You want to… | Use |
|---|---|
| Ask your AI agent (Claude Code, Codex, …) to audit your infrastructure | [Agent skill](#option-a-agent-skill) |
| Run a report from the terminal or on a schedule | [CLI](#option-b-cli) |
| Check infrastructure in CI and upload SARIF | [GitHub Action](#github-action-and-sarif) |
| See what the output looks like first | [Try it without a token](#try-it-without-a-token) |

### Try it without a token

This runs against a synthetic, intentionally insecure fixture. No Hetzner account is needed.

```sh
git clone https://github.com/jpolec/hetzner-cloud-audit-skills
cd hetzner-cloud-audit-skills
uv run hetzner-audit audit \
  --input benchmarks/scenarios/v0.1-insecure.json \
  --format markdown --output demo.md
```

Or just read the pre-generated [sample security report](examples/reports/demo.md) and [sample cost report](examples/reports/demo-cost-v0.3.md).

### 1. Create a read-only token

In [Hetzner Console](https://console.hetzner.com/): **your project → Security → API tokens → Generate API token → Read**.

Never choose **Read & Write**; the tool makes `GET` requests only. The [illustrated token guide](docs/token-setup.md) covers every step, including revocation.

![Token setup: Project → Security → API tokens → Read](docs/assets/token-read-only.png)

### 2. Load it without leaking it

```sh
printf 'Hetzner read-only token: '
IFS= read -rs HCLOUD_TOKEN; printf '\n'
export HCLOUD_TOKEN
```

This keeps the token out of shell history. Never paste it into an agent prompt, command argument, `.env`, screenshot, or report.

### Option A: agent skill

```sh
npx skills add https://github.com/jpolec/hetzner-cloud-audit-skills \
  --skill hetzner-security-audit
```

Then ask your agent:

```text
audit my Hetzner infrastructure
```

Works with Claude Code, OpenAI Codex, and other SKILL.md-compatible agents. The top-level skill loads the network, Linux, Docker, PostgreSQL, Redis, backup, and cost guidance only when the evidence makes it relevant.

### Option B: CLI

```sh
uvx --from 'git+https://github.com/jpolec/hetzner-cloud-audit-skills@v0.3.0' \
  hetzner-audit audit --read-only --no-ssh --format markdown --output audit.md
```

When you are done:

```sh
unset HCLOUD_TOKEN   # then revoke the token in Hetzner Console
```

Treat `audit.md` as sensitive. It contains names, IP addresses, and topology. Do not commit real reports or snapshots to a public repository.

## What the report contains

- **Facts** confirmed by the Hetzner API.
- **Findings** with a complete evidence chain, impact, and remediation.
- **Hypotheses** that need host or runtime evidence before they can be confirmed.
- **Collection gaps** and stale evidence.
- **Controls** that refute an apparent exposure, such as a Cloudflare-only or Tailscale-only source.

Out of the box, the API-only layer checks:

- public SSH, Docker API, Kubernetes API, PostgreSQL, Redis, Elasticsearch, and MongoDB;
- public servers with no cloud firewall attached;
- broad private-network paths from unrelated workloads to DB, auth, or Vault-labelled hosts;
- environment-policy violations, when labels and an owner policy define intent;
- disabled deletion protection on production or foundational resources;
- production state with no observed native backup;
- missing ownership labels;
- stopped-but-billed servers, unattached resources, deprecated types, and rightsizing candidates.

The Hetzner API cannot see host listeners, Docker port publishing, PostgreSQL HBA, Redis ACLs, or guest memory. Those findings stay `needs_validation` and show what evidence is missing.

## Commands

### What is publicly reachable?

```sh
hetzner-audit ask "Can the Internet reach any database?" --input snapshot.json
```

### What can cross a trust boundary?

```sh
hetzner-audit path --from staging-worker --to prod-db \
  --protocol tcp --port 5432 --input snapshot.json
```

![Attack path from staging-worker to prod-db with cited evidence](docs/assets/path-overview.png)

### What changed?

```sh
hetzner-audit snapshot --output before.json --read-only --no-ssh
# ... later ...
hetzner-audit snapshot --output after.json --read-only --no-ssh
hetzner-audit diff before.json after.json --fail-on-regression
```

The diff reports new public edges, asset and fact changes, and collector coverage regressions. A resource that failed to collect is not reported as deleted. Each fact records its source, observation time, collector version, and run ID.

### Why was this flagged?

```sh
hetzner-audit explain HETZ-XLY-002-0123456789abcdef --input snapshot.json
```

This prints the stored evidence chain, attack path, verifier challenge, unresolved prerequisites, and remediation. It does not ask a model to invent a new explanation.

### Tell it what "correct" means: owner policy

Generic best practice is weaker than your own architecture contract. You can write the policy as TOML or JSON:

```toml
[environments.production]
may_receive_from = ["production"]

[services.postgres]
public = false

[services.redis]
public = false

[ssh]
public = false
```

```sh
hetzner-audit audit --policy policies/example-policy.toml \
  --format markdown --output audit.md
```

Observed facts, owner policy, IaC declarations, and inferred hypotheses are kept as separate records.

## Cost audit (experimental)

```sh
npx skills add https://github.com/jpolec/hetzner-cloud-audit-skills \
  --skill hetzner-cost-audit

hetzner-audit cost --metrics-days 30 --format markdown --output cost.md
```

```text
Current catalog estimate:       EUR 220.00/month
Potential savings identified:   EUR 90.00/month · EUR 1,080/year
Confirmed savings:              EUR 0/month

Why zero confirmed?
Guest RAM, filesystem occupancy, owner intent, and rollback evidence are incomplete.
```

Each recommendation shows the current type and cost, CPU p95, the candidate type, the saving, risk, confidence, missing evidence, security and reliability impact, validation, and rollback. Only one candidate per server counts toward the total, so savings are not double-counted.

The cost audit is deliberately conservative:

- a stopped server is still billed;
- CPU-only rightsizing is never confirmed without guest RAM and disk evidence;
- ARM savings require image, dependency, and performance validation;
- the tool has no resize, stop, delete, detach, or purchase action.

![Cost recommendation with evidence and safeguards](docs/assets/cost-overview.png)

## GitHub Action and SARIF

```yaml
- uses: jpolec/hetzner-cloud-audit-skills@v0.3.0
  env:
    HCLOUD_TOKEN: ${{ secrets.HCLOUD_TOKEN }}
  with:
    mode: audit
    policy: policies/infrastructure.toml
    format: sarif
    output: hetzner-audit.sarif
```

Run live collection only from protected `schedule` or `workflow_dispatch` jobs, and never expose the token to fork code. See the full [GitHub Action guide](docs/github-action.md).

SARIF works best when a finding maps to IaC. Runtime-only topology findings are also available as Markdown and JSON, so they are not forced into a fake source location.

## Safety model

- **Read-only.** The code contains no Hetzner `POST`, `PUT`, or `DELETE` call. Use a **Read** token anyway.
- **No SSH, no probing.** Findings come from API state and evidence you supply; the tool never port-scans.
- **No auto-remediation.** Remediation is a plan with validation and rollback steps for a human to review.
- **Secrets are redacted.** Token, password, private-key, and `user_data` fields are stripped from snapshots.

See the [threat model](docs/threat-model.md) and [permissions](docs/permissions.md).

## Capability status

| Capability | v0.3 status |
|---|---|
| Paginated Hetzner Cloud inventory with per-endpoint coverage | Beta |
| Public firewall exposure | Beta |
| Shared-network and lateral cloud paths | Beta (host/runtime stays `needs_validation`) |
| Snapshots, temporal facts, and diff | Beta |
| `path`, `explain`, constrained `ask` | Beta |
| JSON/TOML owner policy | Beta |
| JSON, Markdown, SARIF output | Beta |
| Cost totals and potential savings | Experimental |
| Linux/Docker/PostgreSQL/Redis | Fixture and operator-evidence workflow |
| Live Terraform-state drift | Not complete |
| Kubernetes/CCM/CSI | Planned |
| AWS/GCP/Azure/OCI adapters | Future (shared engine) |
| MCP server | Deferred |

## How it works

```mermaid
flowchart LR
  H[Hetzner GET-only API] --> F[Temporal facts]
  I[IaC and owner policy] --> F
  R[Optional host/runtime evidence] --> F
  F --> G[Typed evidence graph]
  G --> P[Attack paths]
  G --> D[Temporal diff]
  G --> S[Security findings]
  G --> C[Cost and architecture candidates]
  P --> V[Independent challenge]
  D --> V
  S --> V
  C --> V
  V --> O[JSON / Markdown / SARIF]
```

The pipeline is `collect → reason → verify`. The deterministic verifier is a separate component, not an independent human or agent reviewer. Agent-generated candidates without an independent verifier stay `needs_validation`.

More detail: [architecture](docs/architecture.md), [FinOps architecture](docs/finops-architecture.md), [Cloudflare reference analysis](docs/cloudflare-reference.md), [landscape](docs/landscape.md), [roadmap](docs/roadmap.md).

## Benchmark

The synthetic benchmark plants 33 security problems. 23 meet the deterministic evidence contract, and 10 intentionally remain `needs_validation`. This measures fixture behaviour, not real-world detection accuracy. See the [benchmark methodology](benchmarks/README.md).

## Development

```sh
uv sync --extra dev        # or: python -m pip install -e '.[dev]'
uv run ruff check .
uv run mypy src
uv run pytest
./scripts/demo.sh          # regenerate examples/reports
uv run python scripts/validate_artifacts.py
```

Runtime code uses only the Python standard library. Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md). Licensed under Apache-2.0 for its explicit patent grant.

## Maintainer

Created and maintained by [Jakub Połeć](https://github.com/jpolec), founder of [QuantJourney](https://quantjourney.cloud).

Report security issues through [GitHub private vulnerability reporting](SECURITY.md), not a public issue.
