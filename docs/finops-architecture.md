# Cost and cross-domain architecture audits

`hetzner-cost-audit` is an experimental, read-only skill for evidence-backed FinOps decisions. It is deliberately separate from security findings: a cheaper configuration is not automatically safer or more reliable.

The reusable architecture is provider-neutral:

```text
Hetzner / AWS / GCP / Azure / OCI adapters
                    ↓
normalized assets + metrics + prices + declared constraints
                    ↓
cost, security, reliability and performance candidates
                    ↓
independent verification per domain
                    ↓
cross-domain architecture recommendation
```

Provider adapters own API paths, product names, pricing semantics, billing exports, and metric availability. Shared analyzers operate only on normalized facts. This keeps future cloud support from becoming a set of copied provider-specific prompts.

For Hetzner, read-only server metrics provide CPU, disk, and network observations through the server metrics endpoint. Hetzner documents that guest RAM utilization is not available in Console because it requires access inside the server. A rightsizing recommendation therefore remains `needs_validation` until an authorized host or monitoring source supplies memory headroom. Hetzner also bills a cloud server while it exists even when powered off, using hourly billing capped by the monthly price.

Prices must be timestamped and treated as estimates unless reconciled with invoice evidence. Region, currency, VAT, IPv4, traffic, legacy pricing, setup fees, billing horizon, and product availability can change the result.

v0.3 includes an experimental read-only catalog and 30-day CPU/disk/network metrics collector plus stopped-resource, same-architecture rightsizing, and ARM migration candidates. It reports current catalog estimate, maximum non-overlapping potential savings, and confirmed savings separately. Guest RAM, filesystem occupancy, invoice terms, owner intent, SLOs, and migration compatibility remain external evidence; without them a proposed saving stays `needs_validation` and confirmed savings remain zero.

Primary references:

- [Hetzner server metrics implementation](https://github.com/hetznercloud/hcloud-python/blob/main/hcloud/servers/client.py)
- [Why RAM usage is not shown](https://docs.hetzner.com/cloud/servers/faq/#why-is-ram-usage-not-shown-in-hetzner-console)
- [Cloud billing FAQ](https://docs.hetzner.com/cloud/billing/faq/)
