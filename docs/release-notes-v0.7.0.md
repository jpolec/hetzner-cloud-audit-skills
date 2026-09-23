# v0.7.0 release notes

v0.7.0 ships roadmap items v0.6 (host evidence and drift) and v0.7 (beyond one Cloud project) together. The audit can now answer the questions the Cloud API alone cannot: is the port really open on the host, did someone change it by hand, and what about the dedicated servers, buckets, and clusters next to the Cloud project?

## Highlights

- **Host evidence, owner-run.** `hetzner-audit host-bundle` prints a read-only script you review and run on each server. With `--host-bundle`, exposure is decided by flow intersection: Cloud Firewall ∩ host firewall ∩ listener. Unknown layers stay `needs_validation`; they never count as safe.
- **Docker bypass, found.** Ports published by Docker skip UFW and nftables input rules. `HETZ-DKR-005` shows them, with HIGH severity when the Cloud Firewall also admits them.
- **Private-network reality.** Unauthenticated Redis or PostgreSQL reachable from other servers on the private network is now confirmed, because no Cloud Firewall filters that traffic.
- **Drift.** Terraform state or saved plans against runtime, and 30 days of provider actions (rescue mode, console sessions, password resets, protection switched off).
- **Beyond one project.** Several projects in one report, Hetzner Robot (Robot firewall, IPv6, vSwitch), Object Storage (public ACLs and policies, versioning), Kubernetes (NodePorts open on nodes, workloads with node access), and a console checklist for 2FA and tokens.
- **Honest savings.** Theoretical, expected, and verified savings are separate numbers. RAM and disk telemetry gate rightsizing; `diff` measures what a change actually saved.
- **Two new views.** `--view host` shows each server's layers and containers; `--view posture` is a domain × severity matrix with coverage and evidence sources. The architecture map now shows load balancers, Kubernetes, Robot, and buckets.

## Tested how

- Host bundle: fixture-tested, modeled on a real UFW + Docker host, plus adversarial parser cases. It has not yet run live.
- Provider action history: tested on a live project.
- Terraform, Robot, Object Storage, Kubernetes, checklist: tested on documented response shapes only. Object Storage signing matches the AWS SigV4 test vectors.
- An independent adversarial review found about 30 defects before release; all are fixed and covered by regression tests.
- Generated benchmark: 18 rules, 150 projects with clean twins, 1.00 precision and recall.

## Upgrade notes

- Nothing changes for API-only runs, except that `diff` reports a cost delta when both snapshots carry pricing.
- New optional credentials: `HROBOT_USER`/`HROBOT_PASSWORD`, `HETZNER_S3_ACCESS_KEY`/`HETZNER_S3_SECRET_KEY`, `PROMETHEUS_TOKEN`. Keep them out of `.env` files; `doctor` warns if they are there.
