# Roadmap

## v0.2 priorities

1. Complete official-SDK-backed collection and endpoint fixture coverage, including DNS and backup/snapshot relationships.
2. Implement constrained Linux SSH, Docker socket, PostgreSQL catalog, Redis ACL/config, and Terraform plan/state adapters.
3. Add evidence freshness, collector capability manifests, hard size/depth limits, and secret-taint/redaction tests.
4. Add clean-twin benchmarks and independent agent verifier orchestration artifacts.
5. Add a read-only MCP server only after tool authorization and schemas stabilize.

Later extension contracts may support AWS, GCP, OCI, bare metal, Kafka/Redpanda, Vault/OpenBao, nginx, Kubernetes, and Tailscale. Hetzner remains the initial focus; those providers/services are not implemented in v0.1.

