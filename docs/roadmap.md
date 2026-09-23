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

## v0.4.0 — a report you can show to a founder (released 2026-09-23; remaining items move to v0.5)

Goal: one read-only token, zero SSH, a complete and honest provider-level report. Hetzner depth comes before any other provider.

1. ✅ **`hetzner-audit doctor`**: checks the token without printing it, API reachability, per-endpoint access, project scope, optional tools, and whether the report location could leak into Git.
2. ✅ **First-page summary**: scope counts, findings confirmed from the API, hypotheses that need host or runtime validation, collection gaps, catalog cost, and potential versus confirmed savings, always in that order.
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

Also done in v0.4: architecture, per-VM connectivity, and per-VM cost diagrams. Private networks are now modeled as unfiltered by cloud firewalls.

## v0.5.0 — close the gap between collection and analysis (never tagged on its own; ships in v0.7.0)

Driven by an external review that noted the collector was wide and the analyzer narrow:

- Firewall quality (`HETZ-FW-001..004`) and about 30 sensitive TCP/UDP services and ranges.
- Load balancers, certificates, DNS takeover and private records, Storage Boxes, OS end of support, and placement spread. Load balancers, certificates, and DNS are fixture-tested only.
- `HETZ-GOV-004`: servers that policy cannot evaluate because labels are missing; a `sensitivity=high` label.
- CI honesty: `--fail-on none|confirmed|confirmed-high`; hypotheses never fail a job.
- Retry/backoff with `Retry-After`, capped pagination and path search, and Markdown/Mermaid escaping of provider text.
- Cloudflare range provenance and a freshness check.
- Core correctness from an architecture review: semantic flow-set diff, listener ∩ host-firewall confirmation, load balancers in the attack graph, stateful detection, and an honest metrics window.
- SSH key strength and age, `audit.ignore` owner labels, suggested `hcloud` commands, traffic quota and overage, and a generated TP/FP/FN benchmark.

## v0.6 + v0.7 — host evidence, drift, and beyond one project (ship together as v0.7.0)

Done:

1. ✅ **Host evidence bundle** (`host-bundle`): owner-run read-only script; flow intersection across Cloud Firewall, host firewall (UFW, nftables, iptables), and listeners; Docker bypass; sshd; containers; `pg_hba` first-match order; Redis bind and ACL.
2. ✅ **Terraform ↔ runtime drift** from `terraform show -json` state and saved plans.
3. ✅ **Provider `/actions` history** as change signals.
4. ✅ **API-reference-shaped fixtures** for load balancers, certificates, and DNS, run end to end through the collector. (Real anonymized responses still welcome from users who run these resources.)
5. ✅ **Cost evidence**: RAM and disk from node exporter via Prometheus, coverage against the audit window, and theoretical/expected/verified savings.
6. ✅ **Multi-project** snapshots and merge with cross-project trust rules.
7. ✅ **Hetzner Robot**: dedicated servers, Robot firewall, vSwitch, keys.
8. ✅ **Object Storage**: ACLs, bucket policies, versioning.
9. ✅ **Kubernetes correlation**: NodePorts versus node firewalls, workloads with node-level access, CCM/CSI.
10. ✅ **Console checklist** with owner attestations.

Next, in order:

- Live validation of the host bundle, Robot, Object Storage, and Kubernetes on real accounts, and anonymized fixtures from those runs.
- firewalld zones and CSF in the host-firewall evaluator (today they stay "unknown").
- Evidence age and baseline selection for `diff` in CI, and a PR comment.

## Later

- Cross-domain architecture recommendations that combine cost, exposure, and recovery into one reviewed change.
- An independent agent verifier that sees only the finding, schema, and evidence, never the hunter's reasoning.

## Not planned for now

- AWS, GCP, Azure, and OCI should be provider adapters feeding the shared fact/graph/reasoning engine—not copied prompt repositories.
- A read-only MCP facade remains deferred until authorization, schemas, query limits, and redaction behavior stabilize.
- No automatic provider remediation is planned for the alpha line. Remediation remains a reviewed plan with validation and rollback.
- No dashboard, SaaS backend, graph database, or full CIS/NIST compliance mapping.
