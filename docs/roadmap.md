# Roadmap

## v0.3 priorities

1. Complete official-SDK-backed collection and endpoint fixture coverage, including DNS and backup/snapshot relationships.
2. Implement constrained Linux SSH, Docker socket, PostgreSQL catalog, Redis ACL/config, and Terraform plan/state adapters.
3. Add evidence freshness, collector capability manifests, hard size/depth limits, and secret-taint/redaction tests.
4. Add clean-twin benchmarks and independent agent verifier orchestration artifacts.
5. Add a read-only MCP server only after tool authorization and schemas stabilize.
6. Implement Hetzner metrics/pricing adapters and benchmarked rules for the experimental `hetzner-cost-audit` skill.

Later extension contracts may support AWS, GCP, Azure, OCI, bare metal, Kafka/Redpanda, Vault/OpenBao, nginx, Kubernetes, and Tailscale. Cost adapters share normalized architecture-recommendation contracts rather than copied provider prompts. Hetzner remains the initial focus; those providers/services are not implemented in v0.2.
