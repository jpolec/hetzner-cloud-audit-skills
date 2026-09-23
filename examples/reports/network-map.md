# Hetzner Network Map

Collected at: 2026-09-23T07:22:24.367180+00:00 · servers: 18 · private: 14 · proxied: 3 · public: 1

```mermaid
flowchart LR
  src_cloudflare(["Cloudflare only"])
  src_tailscale(["Tailscale tailnet"])
  src_world(("Internet (any address)"))
  subgraph net["acme-net 10.0.0.0/16"]
    subgraph net_edge["Edge & web"]
      direction TB
      n_acme_batch_1["acme-batch-1<br/><small>batch-web · cx33 · nbg1</small>"]
      n_acme_edge_1["acme-edge-1<br/><small>edge · cx23 · fsn1</small>"]
      n_acme_web_1["acme-web-1<br/><small>fe · cx23 · fsn1</small>"]
    end
    subgraph net_security["Identity & secrets"]
      direction TB
      n_acme_orchestrator_1["acme-orchestrator-1<br/><small>identity · cx23 · fsn1</small>"]
    end
    subgraph net_data["Data"]
      direction TB
      n_acme_api_db_1["acme-api-db-1<br/><small>db · cx23 · fsn1</small>"]
      n_acme_data["acme-data<br/><small>data-platform · cx23 · fsn1</small>"]
      n_acme_replica["acme-replica<br/><small>replica · cax31 · fsn1</small>"]
      n_acme_warehouse["acme-warehouse<br/><small>warehouse · cpx32 · hel1</small>"]
    end
    subgraph net_app["Applications"]
      direction TB
      n_acme_agents_1["acme-agents-1<br/><small>agent-gateway · cax11 · fsn1</small>"]
      n_acme_api_app_1["acme-api-app-1<br/><small>app · cpx22 · fsn1</small>"]
      n_acme_bus["acme-bus<br/><small>acme-bus · cpx22 · fsn1</small>"]
      n_acme_worker_1["acme-worker-1<br/><small>cx22 · hel1</small>"]
    end
    subgraph net_other["Other"]
      direction TB
      n_acme_catalog["acme-catalog<br/><small>catalog · cax11 · fsn1</small>"]
      n_acme_ingest_1["acme-ingest-1<br/><small>cpx32 · fsn1</small>"]
      n_acme_ingest_2["acme-ingest-2<br/><small>vendor-feed · cx33 · fsn1</small>"]
      n_acme_sim["acme-sim<br/><small>scenario · cpx32 · fsn1</small>"]
    end
  end
  subgraph nonet["No private network"]
    subgraph nonet_security["Identity & secrets"]
      direction TB
      n_acme_auth_1["acme-auth-1<br/><small>auth · cx23 · fsn1</small>"]
      n_acme_vault_1["acme-vault-1<br/><small>vault · cx23 · fsn1</small>"]
    end
  end
  src_cloudflare -->|"tcp/80, tcp/443"| n_acme_batch_1
  src_cloudflare -->|"tcp/80, tcp/443"| n_acme_data
  src_cloudflare -->|"tcp/80, tcp/443"| n_acme_edge_1
  src_world ==>|"tcp/80, tcp/443"| n_acme_sim
  src_tailscale -.->|"admin & WireGuard"| net
  src_tailscale -.->|"admin & WireGuard"| nonet
  classDef public fill:#43300f,stroke:#fbbf24,color:#fef3c7
  class n_acme_sim public
  classDef proxied fill:#0f3a2e,stroke:#34d399,color:#d1fae5
  class n_acme_batch_1,n_acme_data,n_acme_edge_1 proxied
  classDef private fill:#13233a,stroke:#60a5fa,color:#dbeafe
  class n_acme_agents_1,n_acme_api_app_1,n_acme_api_db_1,n_acme_auth_1,n_acme_bus,n_acme_catalog,n_acme_ingest_1,n_acme_ingest_2,n_acme_orchestrator_1,n_acme_replica,n_acme_vault_1,n_acme_warehouse,n_acme_web_1,n_acme_worker_1 private
```

Exposure: **critical** = sensitive port or all ports open to any address, or no cloud firewall; **public** = other ports open to any address; **proxied** = reachable only through Cloudflare; **private** = no public ingress except the Tailscale WireGuard port.

| Server | Group | Type | Exposure | Public ingress | Private / admin ingress |
|---|---|---|---|---|---|
| acme-agents-1 | Applications | cax11 | private | none (ICMP only) | Tailscale tailnet: udp/41641 (WireGuard) |
| acme-api-app-1 | Applications | cpx22 | private | none (ICMP only) | Tailscale tailnet: tcp/2222, udp/41641 (WireGuard), tcp/all, udp/all; Private network: tcp/all, udp/all |
| acme-api-db-1 | Data | cx23 | private | none (ICMP only) | Tailscale tailnet: tcp/2222, udp/41641 (WireGuard), tcp/all, udp/all; Private network: tcp/all, udp/all |
| acme-auth-1 | Identity & secrets | cx23 | private | none (ICMP only) | Tailscale tailnet: udp/41641 (WireGuard) |
| acme-batch-1 | Edge & web | cx33 | proxied | Cloudflare only: tcp/80, tcp/443 | Tailscale tailnet: udp/41641 (WireGuard) |
| acme-bus | Applications | cpx22 | private | none (ICMP only) | Tailscale tailnet: udp/41641 (WireGuard) |
| acme-catalog | Other | cax11 | private | none (ICMP only) | Tailscale tailnet: tcp/2222, tcp/8000, udp/41641 (WireGuard); Private network: tcp/8000, tcp/all, udp/all |
| acme-data | Data | cx23 | proxied | Cloudflare only: tcp/80, tcp/443 | Tailscale tailnet: tcp/2222, udp/41641 (WireGuard); Private network: tcp/all, udp/all |
| acme-edge-1 | Edge & web | cx23 | proxied | Cloudflare only: tcp/80, tcp/443 | Tailscale tailnet: tcp/2222, udp/41641 (WireGuard), tcp/all, udp/all; Private network: tcp/all, udp/all |
| acme-ingest-1 | Other | cpx32 | private | none (ICMP only) | Tailscale tailnet: udp/41641 (WireGuard), tcp/all |
| acme-ingest-2 | Other | cx33 | private | none (ICMP only) | Tailscale tailnet: tcp/2222, tcp/9101, udp/41641 (WireGuard); Private network: tcp/9101, tcp/all, udp/all |
| acme-orchestrator-1 | Identity & secrets | cx23 | private | none (ICMP only) | Tailscale tailnet: tcp/2222, udp/41641 (WireGuard), tcp/all, udp/all; Private network: tcp/all, udp/all |
| acme-replica | Data | cax31 | private | none (ICMP only) | Tailscale tailnet: tcp/2222, udp/41641 (WireGuard), tcp/all, udp/all; Private network: tcp/all, udp/all |
| acme-sim | Other | cpx32 | public | Internet (any address): tcp/80, tcp/443 | Tailscale tailnet: tcp/2222, udp/41641 (WireGuard); Private network: tcp/all, udp/all |
| acme-vault-1 | Identity & secrets | cx23 | private | none (ICMP only) | Tailscale tailnet: udp/41641 (WireGuard) |
| acme-warehouse | Data | cpx32 | private | none (ICMP only) | Tailscale tailnet: tcp/2222, tcp/9102, udp/41641 (WireGuard); Private network: tcp/9102, tcp/all, udp/all |
| acme-web-1 | Edge & web | cx23 | private | none (ICMP only) | Tailscale tailnet: tcp/2222, udp/41641 (WireGuard), tcp/all, udp/all; Private network: tcp/all, udp/all |
| acme-worker-1 | Applications | cx22 (deprecated) | private | none (ICMP only) | Tailscale tailnet: udp/41641 (WireGuard) |

Unattached volumes: acme-batch-data

Public IP addresses are intentionally omitted. The map shows provider firewall intent, not host or application controls.
