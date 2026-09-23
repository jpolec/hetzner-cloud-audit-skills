# Hetzner Network Map

Collected at: 2026-09-19T06:12:00+00:00 · servers: 14 · private: 10 · proxied: 3 · public: 1

```mermaid
flowchart LR
  src_cloudflare(["Cloudflare only"])
  src_tailscale(["Tailscale tailnet"])
  src_world(("Internet (any address)"))
  subgraph net["core-net 10.40.0.0/16"]
    subgraph net_edge["Edge & web"]
      direction TB
      n_gw_1["gw-1<br/><small>edge · cx23 · fsn1</small>"]
      n_web_1["web-1<br/><small>fe · cx33 · nbg1</small>"]
      n_web_2["web-2<br/><small>web · cx23 · fsn1</small>"]
    end
    subgraph net_security["Identity & secrets"]
      direction TB
      n_sso_1["sso-1<br/><small>identity · cx23 · nbg1</small>"]
    end
    subgraph net_data["Data"]
      direction TB
      n_pg_main["pg-main<br/><small>db · cx33 · fsn1</small>"]
      n_pg_replica["pg-replica<br/><small>replica · cx33 · nbg1</small>"]
    end
    subgraph net_app["Applications"]
      direction TB
      n_api_1["api-1<br/><small>app · cpx32 · fsn1</small>"]
    end
    subgraph net_other["Other"]
      direction TB
      n_analytics_1["analytics-1<br/><small>analytics · cpx22 · fsn1</small>"]
      n_etl_1["etl-1<br/><small>etl · cx43 · fsn1</small>"]
      n_jobs_1["jobs-1<br/><small>jobs · cx22 · fsn1</small>"]
      n_lake_1["lake-1<br/><small>lake · cpx42 · fsn1</small>"]
      n_preview_1["preview-1<br/><small>preview · cpx22 · hel1</small>"]
    end
  end
  subgraph nonet["No private network"]
    subgraph nonet_security["Identity & secrets"]
      direction TB
      n_idp_1["idp-1<br/><small>auth · cx23 · fsn1</small>"]
      n_secrets_1["secrets-1<br/><small>vault · cx23 · hel1</small>"]
    end
  end
  src_cloudflare -->|"tcp/80, tcp/443"| n_analytics_1
  src_cloudflare -->|"tcp/80, tcp/443"| n_gw_1
  src_world ==>|"tcp/80, tcp/443"| n_preview_1
  src_cloudflare -->|"tcp/80, tcp/443"| n_web_2
  src_tailscale -.->|"admin & WireGuard"| net
  src_tailscale -.->|"admin & WireGuard"| nonet
  classDef public fill:#43300f,stroke:#fbbf24,color:#fef3c7
  class n_preview_1 public
  classDef proxied fill:#0f3a2e,stroke:#34d399,color:#d1fae5
  class n_analytics_1,n_gw_1,n_web_2 proxied
  classDef private fill:#13233a,stroke:#60a5fa,color:#dbeafe
  class n_api_1,n_etl_1,n_idp_1,n_jobs_1,n_lake_1,n_pg_main,n_pg_replica,n_secrets_1,n_sso_1,n_web_1 private
```

Exposure: **critical** = sensitive port or all ports open to any address, or no cloud firewall; **public** = other ports open to any address; **proxied** = reachable only through Cloudflare; **private** = no public ingress except the Tailscale WireGuard port. Hetzner Cloud Firewalls do not filter private networks, so members of one network reach each other on every port.

| Server | Group | Type | Exposure | Public ingress | Private / admin ingress |
|---|---|---|---|---|---|
| analytics-1 | Other | cpx22 | proxied | Cloudflare only: tcp/80, tcp/443 | Tailscale tailnet: tcp/22, udp/41641 (WireGuard); core-net: all ports (not filtered by cloud firewalls) |
| api-1 | Applications | cpx32 | private | none (ICMP only) | Tailscale tailnet: tcp/22, udp/41641 (WireGuard), tcp/all, udp/all; core-net: all ports (not filtered by cloud firewalls) |
| etl-1 | Other | cx43 | private | none (ICMP only) | Tailscale tailnet: udp/41641 (WireGuard), tcp/all; core-net: all ports (not filtered by cloud firewalls) |
| gw-1 | Edge & web | cx23 | proxied | Cloudflare only: tcp/80, tcp/443 | Tailscale tailnet: tcp/22, udp/41641 (WireGuard), tcp/all, udp/all; core-net: all ports (not filtered by cloud firewalls) |
| idp-1 | Identity & secrets | cx23 | private | none (ICMP only) | Tailscale tailnet: udp/41641 (WireGuard) |
| jobs-1 | Other | cx22 (deprecated) | private | none (ICMP only) | Tailscale tailnet: udp/41641 (WireGuard); core-net: all ports (not filtered by cloud firewalls) |
| lake-1 | Other | cpx42 | private | none (ICMP only) | Tailscale tailnet: tcp/22, tcp/7001, udp/41641 (WireGuard); core-net: all ports (not filtered by cloud firewalls) |
| pg-main | Data | cx33 | private | none (ICMP only) | Tailscale tailnet: tcp/22, udp/41641 (WireGuard), tcp/all, udp/all; core-net: all ports (not filtered by cloud firewalls) |
| pg-replica | Data | cx33 | private | none (ICMP only) | Tailscale tailnet: tcp/22, udp/41641 (WireGuard), tcp/all, udp/all; core-net: all ports (not filtered by cloud firewalls) |
| preview-1 | Other | cpx22 | public | Internet (any address): tcp/80, tcp/443 | Tailscale tailnet: tcp/22, udp/41641 (WireGuard); core-net: all ports (not filtered by cloud firewalls) |
| secrets-1 | Identity & secrets | cx23 | private | none (ICMP only) | Tailscale tailnet: udp/41641 (WireGuard) |
| sso-1 | Identity & secrets | cx23 | private | none (ICMP only) | Tailscale tailnet: tcp/22, udp/41641 (WireGuard), tcp/all, udp/all; core-net: all ports (not filtered by cloud firewalls) |
| web-1 | Edge & web | cx33 | private | none (ICMP only) | Tailscale tailnet: tcp/22, udp/41641 (WireGuard), tcp/all, udp/all; core-net: all ports (not filtered by cloud firewalls) |
| web-2 | Edge & web | cx23 | proxied | Cloudflare only: tcp/80, tcp/443 | Tailscale tailnet: udp/41641 (WireGuard); core-net: all ports (not filtered by cloud firewalls) |

Unattached volumes: orphan-data

Public IP addresses are intentionally omitted. The map shows provider firewall intent, not host or application controls.
