# hetzner-security-skills

**Agentic security auditing for Hetzner infrastructure.**

Traditional scanners inspect layers independently. This project correlates current Hetzner Cloud topology, network policy, Linux hosts, containers, PostgreSQL, Redis, IaC intent, and external scanner signals—then applies a deterministic evidence contract and supports a fresh independent agent challenge.

> This is an independent open-source project and is not affiliated with or endorsed by Hetzner or Cloudflare. v0.1.x is alpha and is not production-ready.

![Synthetic benchmark CLI showing verified cross-layer results](docs/assets/demo-overview.png)

## The difference

```text
Terraform says:  SSH only from 100.64.0.0/10
Hetzner says:    22/tcp accepts 0.0.0.0/0
Attack path:     Internet → tcp/22 → admin server
Result:          MEDIUM · confirmed provider-policy drift · confidence 0.98
Reachability:    needs host firewall + listener evidence
```

The system does not merely concatenate hcloud, Trivy, and database warnings. It follows `collect → reason → verify`:

```mermaid
flowchart LR
  H[Hetzner API] --> F[Normalized facts]
  R[Repository / IaC] --> F
  L[Linux / Docker] --> F
  D[PostgreSQL / Redis] --> F
  S[Trivy / Grype / other signals] --> F
  F --> G[Typed attack graph]
  G --> C[Cross-layer candidates]
  C --> V{Evidence-contract verifier}
  V -->|complete evidence| OK[confirmed]
  V -->|decisive fact missing| NV[needs_validation]
  V -->|control refutes path| NO[rejected]
```

![Synthetic cross-layer PostgreSQL finding](docs/assets/demo-finding.png)

## Install for an AI coding agent

The intended UX is one top-level skill that loads only the relevant modules:

```sh
npx skills add https://github.com/jpolec/hetzner-security-skills \
  --skill hetzner-security-audit
```

Then ask your agent:

```text
audit my Hetzner infrastructure
```

The skill is agent-neutral and designed for Claude Code, OpenAI Codex, and other SKILL.md-compatible agents. The skill contains the audit workflow, not an executable installer. When `hetzner-sec` is unavailable, it guides the agent to use the checked-out source or request approval before running the pinned CLI with `uvx`.

For a one-off CLI run without a persistent install:

```sh
uvx --from 'git+https://github.com/jpolec/hetzner-security-skills@v0.1.1' \
  hetzner-sec --help
```

## Install the CLI

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
hetzner-sec --help
```

Or install the tagged release with `uv`:

```sh
uv tool install 'git+https://github.com/jpolec/hetzner-security-skills@v0.1.1'
```

Offline synthetic demo—no token, SSH, Docker daemon, or network access required:

```sh
hetzner-sec audit \
  --input benchmarks/scenarios/v0.1-insecure.json \
  --format markdown \
  --output report.md \
  --coverage-ledger coverage-ledger.json
```

## Create a read-only Hetzner API token

Create a dedicated token in the [Hetzner Console](https://console.hetzner.com/):

1. Open the project you want to audit.
2. Select **Security** in the left menu, then **API tokens**.
3. Select **Generate API token** and give it an audit-specific description.
4. Choose **Read** — not **Read & Write**. Hetzner documents that `Read` tokens can perform only `GET` requests.
5. Copy the token immediately into a password manager; Hetzner shows the full value only once.

Tokens are bound to one project. Create and audit with a separate read-only token for every project. Load it without echoing it or placing it in shell history:

```sh
printf 'Hetzner read-only token: '
IFS= read -rs HCLOUD_TOKEN
printf '\n'
export HCLOUD_TOKEN
```

Read-only live inventory:

```sh
hetzner-sec inventory --format json --output inventory.json --read-only --no-ssh
hetzner-sec audit --format json --output findings.json --read-only --no-ssh
unset HCLOUD_TOKEN
```

Never paste the token into a prompt, command argument, `.env` file, repository, or report. Revoke it from the same **Security → API tokens** page when it is no longer needed. `--dry-run` performs no API request. The collector contains fixed `GET` operations and no provider mutation method. It deliberately does not probe token permissions with a write request; confirm **Read** in Hetzner Console.

See the complete [token setup and revocation guide](docs/token-setup.md) and Hetzner's official [token generation instructions](https://docs.hetzner.com/cloud/api/getting-started/generating-api-token/).

## Use cases

### Detect reviewed-IaC drift

Compare declared firewall intent with current Hetzner state. A mismatch becomes material only when it changes a trust boundary or reachable service path.

### Find private-network lateral movement

Show that a staging workload can reach a production database even when PostgreSQL is not public. Join environment labels, shared-network edges, host filtering, Docker routing, listener state, and HBA/auth context.

### Contextualize a container CVE

Map a Trivy or Grype signal to the actual container, host, public/private path, and compensating controls. A vulnerability remains visible while exposure changes priority and confidence.

### Audit database controls in context

Evaluate ordered `pg_hba.conf`, roles, TLS, grants, Redis protected mode/ACLs, and service bind addresses together with provider and host network controls. A broad bind alone is not automatically a finding.

### Build a reviewable security baseline

Use stable findings, evidence records, and a deterministic coverage ledger in CI. Later runs prioritize changed evidence and visible gaps instead of repeating a free-form scan.

### Correlate cost, security, and reliability

The experimental `hetzner-cost-audit` skill treats cost optimization as an architecture decision. It can combine a verified rightsizing candidate with private-network and restore-readiness work without letting savings weaken security or resilience:

```text
Cost:        database host is oversized over a representative window
Security:    database should not have a public path
Reliability: no recent restore-test evidence
Decision:    validate resize + move private + establish tested recovery
```

Install it independently with `npx skills add https://github.com/jpolec/hetzner-security-skills --skill hetzner-cost-audit`. The provider-neutral recommendation schema is designed for later AWS, GCP, Azure, and OCI adapters. v0.1.1 provides the methodology and schema, not automated saving claims.

## Implemented checks

v0.1 exposes 16 rule IDs across eight categories:

| Category | Examples |
|---|---|
| Hetzner/network | public SSH, Docker API, Kubernetes API, PostgreSQL, Redis; public hosts with missing firewall evidence |
| IaC drift | declared source ranges versus observed runtime access |
| Cross-layer | dev/staging → production PostgreSQL or Redis over a proven graph path |
| Docker | privileged mode, Docker socket, host PID, host network |
| PostgreSQL | broad `trust` HBA, unexpected superusers |
| Redis | broad bind + protected mode off + no observed authentication |
| Resilience | production stateful assets without complete backup evidence |
| CVE context | scanner signal mapped to asset and public reachability |

The emphasis is quality over rule count. Absence-based findings remain `needs_validation` until collector completeness is proven.

## Skills

- `hetzner-security-audit` — top-level reconnaissance, coverage, correlation, verification, and reporting.
- `hetzner-cloud-audit` — read-only provider inventory.
- `hetzner-network-audit` — topology and reachability.
- `linux-security-audit` — explicitly authorized read-only host inspection.
- `docker-security-audit` — runtime isolation and network context.
- `postgres-security-audit` — HBA, roles, TLS, grants, operations, and cross-layer paths.
- `redis-security-audit` — protected mode, ACL/TLS, command surface, persistence, and reachability.
- `hetzner-backup-audit` — provider and application recovery evidence.
- `hetzner-cost-audit` — experimental rightsizing and cross-domain FinOps architecture decisions.

The workflow is inspired by Cloudflare's independently developed [security-audit-skill](https://github.com/cloudflare/security-audit-skill). This repository is not a fork or dependency. The exact comparison and attribution are in [docs/cloudflare-reference.md](docs/cloudflare-reference.md).

## Output

```sh
hetzner-sec audit --format json
hetzner-sec audit --format markdown
hetzner-sec audit --format sarif
hetzner-sec network --input snapshot.json --severity high --verify
hetzner-sec postgres --input snapshot.json --verify
hetzner-sec docker --input snapshot.json --verify
hetzner-sec coverage --input snapshot.json > coverage-ledger.json
```

Every record separates severity from confidence and carries assets, expected/actual state, evidence, attack path, prerequisites, impact, verifier result, remediation, references, and discovery time. Schemas live in [`schemas/`](schemas/).

## Safety model

- Read-only Hetzner collection by construction; no create/update/delete methods.
- SSH off by default and allowed only with explicit operator configuration.
- No live exploitation, brute force, restarts, firewall changes, or active scanning.
- Repository content, labels, resource names, and scanner output are untrusted data—not agent instructions.
- Secrets are never required in command arguments and sensitive property names are redacted.
- External scanners are signal providers; their warnings are not automatically confirmed.

Read [permissions](docs/permissions.md), the [threat model](docs/threat-model.md), and [security policy](SECURITY.md) before live use.

## Benchmark status

The synthetic benchmark plants 33 known problems: 23 meet the deterministic evidence contract and 10 remain `needs_validation` by design. It covers the required drift, private PostgreSQL path, and non-public CVE scenarios. Unit tests also exercise clean VPN-scoped SSH, unattached firewall rules, missing downstream reachability, and scanner signals without runtime applicability.

This is fixture recall—not proof of real-world accuracy. See [benchmarks/README.md](benchmarks/README.md) for methodology and limitations.

## Development

```sh
python -m pip install -e '.[dev]'
ruff check .
mypy src
pytest
python -m build
gitleaks detect --no-banner --redact --no-git
```

The runtime has no third-party Python dependencies. Tests can also run with the standard library:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Architecture and research

- [Architecture](docs/architecture.md)
- [Landscape and gap analysis](docs/landscape.md)
- [Cloudflare reference analysis](docs/cloudflare-reference.md)
- [Threat model](docs/threat-model.md)
- [Roadmap](docs/roadmap.md)
- [Cost and multi-cloud architecture](docs/finops-architecture.md)

## Limitations

The API collector is intentionally minimal and has not been tested against a real project in this environment. Linux/SSH, Docker runtime, PostgreSQL catalog, Redis runtime, Terraform state, and automated cost/metrics adapters are specified but not fully implemented. The graph uses normalized evidence and cannot infer uncollected host/network controls. The deterministic verifier is component-separated but not equivalent to a fresh human or agent reviewer. MCP is deferred. Review every high-impact result before action.

## License

Apache License 2.0. It was chosen over MIT for its explicit patent grant and termination provisions, useful for a security tool expected to accept broad external contributions. See [LICENSE](LICENSE).
