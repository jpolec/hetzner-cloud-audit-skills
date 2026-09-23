# Roadmap

## v0.3 — depth before breadth

The release target is one defensible first run: one read-only project token, zero SSH, and a report suitable for an infrastructure owner.

- Production-shaped, paginated Hetzner collection with per-endpoint coverage and partial-failure reporting.
- Temporal fact envelope, full snapshots, coverage-aware `diff`, and first-observed timestamps.
- Typed attack graph plus `path`, `explain`, and constrained `ask` commands.
- API-only exposure, private lateral-path, backup, protection, ownership, lifecycle, and cost signals.
- JSON/TOML owner policy evaluated separately from observed state.
- GitHub composite action, SARIF, Markdown job artifacts, and safe live-workflow guidance.
- Catalog cost baseline, stopped-resource savings, CPU p95 candidates, and non-overlapping savings totals.

## v0.3.1 — first real-project run (done)

- `map`: network topology as Mermaid, SVG (light and dark), or JSON, with trust-classified firewall sources and no public IPs.
- `ask` no longer treats a public IP as permitted traffic; direct exposure and indirect pivots are reported separately.
- New rules: deprecated server types (`HETZ-GOV-003`) and web origins that bypass Cloudflare (`HETZ-NET-006`).
- Personal data redaction in snapshots; grouped Markdown findings; PyPI distribution `hetzner-audit`.

## v0.4 — a report you can show to a founder

Goal: one read-only token, zero SSH, a complete and honest provider-level report. Hetzner depth comes before any other provider.

1. **`hetzner-audit doctor`**: checks the token without printing it, API reachability, per-endpoint access, project scope, optional tools, and whether the report location could leak into Git.
2. **First-page summary**: scope counts, findings confirmed from the API, hypotheses that need host or runtime validation, collection gaps, catalog cost, and potential versus confirmed savings, always in that order.
3. **Production-grade collector**:
   - retry and backoff for 429 and 5xx;
   - explicit status for every endpoint;
   - detection of partial responses and freshness;
   - stable asset IDs;
   - firewall attachment through label selectors;
   - per-location prices;
   - full-window CPU, disk, and network metrics;
   - load-balancer targets, snapshots, and backups.
4. **Anonymized real-response fixtures** for every supported endpoint, plus 20+ clean-twin cases in the benchmark (localhost-only listeners, unpublished Docker ports, HBA rejections, selector-attached firewalls, off-Hetzner backups, collector failures).
5. **Terraform ↔ runtime drift** from `terraform show -json`, saved plans, and read-only state:
   - firewall source ranges;
   - networks and attachments;
   - public IPs;
   - backups;
   - deletion protection;
   - labels, volumes, and load balancers.

   The tool never runs `terraform apply` and never writes state.
6. **Host evidence bundle** (`host-bundle`): an opt-in, versioned allowlist of read-only commands. It covers listeners, host firewall, sshd, Docker inspect and published ports, PostgreSQL HBA, and Redis config and ACL. `path` uses the bundle to turn `cloud_path_present` into `reachable` or `rejected`.
7. **Continuous diff in CI**:
   - new exposures and trust paths;
   - recovery regressions;
   - cost changes;
   - evidence age and baseline selection;
   - a PR comment.
8. **Cost evidence**: RAM, disk, and network p95 from Prometheus or node exporter, operator CSV/JSON, and billing exports. Downsizing is never confirmed without RAM, disk, owner intent, and rollback.

## Later

- Cross-domain architecture recommendations that combine cost, exposure, and recovery into one reviewed change.
- An independent agent verifier that sees only the finding, schema, and evidence, never the hunter's reasoning.
- Kubernetes on Hetzner: correlation only (kube-hetzner, CCM, CSI, public API server, NodePort, node firewalls), not a full Kubernetes audit.

## Not planned for now

- AWS, GCP, Azure, and OCI should be provider adapters feeding the shared fact/graph/reasoning engine—not copied prompt repositories.
- A read-only MCP facade remains deferred until authorization, schemas, query limits, and redaction behavior stabilize.
- No automatic provider remediation is planned for the alpha line. Remediation remains a reviewed plan with validation and rollback.
- No dashboard, SaaS backend, graph database, or full CIS/NIST compliance mapping.
