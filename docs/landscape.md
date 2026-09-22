# Landscape and gap analysis

Research date: 2026-09-22. This review favors primary project documentation and repositories.

## What already exists

Hetzner maintains the [Cloud API](https://docs.hetzner.cloud/), [hcloud CLI](https://github.com/hetznercloud/cli), official [Python](https://github.com/hetznercloud/hcloud-python) and [Go](https://github.com/hetznercloud/hcloud-go) libraries, the [Terraform provider](https://github.com/hetznercloud/terraform-provider-hcloud), and the [Ansible collection](https://github.com/ansible-collections/hetzner.hcloud). These are mature inventory/provisioning primitives, not security reasoning systems. Community hardening material is useful but generally host- or template-scoped; this review found no mature Hetzner-focused project that joins provider state, host/runtime state, database controls, repository intent, and attack paths.

Mature signal providers already solve narrower problems:

| Tool | Keep as the source of truth for | Do not duplicate |
|---|---|---|
| [Trivy](https://trivy.dev/) / [Grype](https://github.com/anchore/grype) | image/filesystem CVEs, SBOM-linked package evidence | vulnerability databases and version matching |
| [Semgrep](https://semgrep.dev/docs/) / [CodeQL](https://codeql.github.com/docs/) | source data-flow/static-analysis signals | language-specific query engines |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | secret-pattern signals | secret detector catalog |
| [Checkov](https://www.checkov.io/) / [tfsec](https://aquasecurity.github.io/tfsec/) | IaC misconfiguration signals | generic Terraform checks |
| Docker tooling | image/runtime facts | container engine and image inspection |
| [pgAudit](https://www.pgaudit.org/) | PostgreSQL audit logging | database audit-log generation |
| PostgreSQL catalogs / Redis config and ACL APIs | authoritative service configuration facts | service configuration engines |

[Cloudflare's security-audit-skill](https://github.com/cloudflare/security-audit-skill) is the strongest methodological reference: reconnaissance, deterministic coverage, isolated hunting, independent verification, three verdicts, schemas, and additive runs. It is source-code focused and intentionally avoids live deployment claims. See [cloudflare-reference.md](cloudflare-reference.md).

Agent Skills use a small `SKILL.md` package with YAML metadata and procedural Markdown. This makes the audit method portable across compatible coding agents. MCP can expose typed tools, including read-only annotations, but annotations are hints rather than a security boundary. Adding an MCP server before the data contracts stabilize would increase attack surface without improving the v0.1 local workflow.

## The real gap

The missing product is not another scanner. It is an evidence join and adversarial reasoning layer:

```text
declared intent + current cloud graph + host filtering + container publication
              + database bind/auth + external scanner signal
                                ↓
                    reachable trust-boundary path
                                ↓
                 independently challenged finding
```

Provider firewalls cannot show whether PostgreSQL binds inside a container. PostgreSQL configuration cannot show which staging subnet can route to it. Trivy cannot decide whether the affected service is reachable. Terraform cannot prove runtime state still matches a reviewed plan. The useful unit is the complete path, not the isolated warning.

## Integration boundaries

v0.1 owns normalization, stable evidence references, attack-graph construction, cross-layer rules, drift comparison, verifier state, coverage accounting, and reporting. It ingests existing tool JSON as signals. It does not download vulnerability databases, execute third-party scanners implicitly, mutate Terraform state, or probe live services.

## Agent-native versus CLI-native

The CLI should deterministically collect, normalize, evaluate known rules, validate schemas, and render reports. The agent skill should perform scope negotiation, architecture reconstruction, module selection, evidence-gap reasoning, hypothesis generation, coverage criticism, and independent reviewer orchestration. This division keeps repeatable mechanics out of prompts while reserving contextual judgment for the agent.

## v0.1 decision

Ship an independent Apache-2.0 Python repository. Use an API-GET-only collector, offline fixtures, a small typed graph, JSON/Markdown/SARIF, and installable skills. Defer MCP until the tool schemas and authorization model have real user feedback. Do not claim comprehensive or production-ready coverage.

