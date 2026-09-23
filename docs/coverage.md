# What hetzner-audit sees

Every component the audit recognizes, how it recognizes it, what it checks, and where the evidence comes from. **Status** is honest about testing:

- **live**: run against a real Hetzner project by the maintainer;
- **fixture**: tested on documented response shapes or synthetic data with clean twins, not yet on a live account;
- **not verifiable**: recognized only if you tell the audit, because the provider publishes no complete data;
- **planned**: not implemented yet.

The tool never connects to your servers. Host evidence comes from a read-only script you review and run yourself (`hetzner-audit host-bundle`).

## Hetzner Cloud (read-only API token)

| Component | What it checks | Evidence | Status |
|---|---|---|---|
| Servers, firewalls, networks | public exposure (~30 services), firewall quality, IPv4/IPv6 drift, no firewall, private-network blast radius | Cloud API | live |
| Volumes, primary and floating IPs, snapshots | unattached or idle resources, cost | Cloud API | live |
| Storage Boxes | reachable from outside Hetzner, no snapshot plan | Hetzner API | live |
| SSH keys | weak algorithm or size, age | Cloud API | live (no weak key present) |
| Images, server types | OS end of support, deprecated types and replacements | Cloud API | live |
| Pricing, CPU metrics, traffic | catalog cost, rightsizing candidates, traffic quota | Cloud API | live |
| Provider actions (30 days) | rescue, console, password reset, rebuild, protection off, firewall removed | Cloud API `/actions` | live |
| Server egress (outbound rules) | servers that may connect anywhere; per-role egress policy (`HETZ-EGR-001`); new egress in `diff --regression-policy strict` | Cloud API | live |
| Load balancer IP targets | resolved to Cloud servers or Robot dedicated servers, else shown as an endpoint | Cloud API + Robot | fixture |
| Load balancers, certificates, DNS zones | plain HTTP, unhealthy or single targets, backends reachable around the LB, expiring or failing certificates, dangling DNS records | Cloud API | fixture |
| Placement groups | replicas outside a spread group | Cloud API | fixture |

## Edge proxies and CDNs in front of an origin

A firewall source is attributed to a provider only when it lies entirely inside that provider's published ranges. Each list is dated and refreshed with `scripts/update_provider_ranges.py` (`--check` reports changes). When some servers accept web traffic only from a provider and another server accepts it from anywhere, `HETZ-NET-006` names the provider that is being bypassed.

| Provider | Ranges from | Status |
|---|---|---|
| Cloudflare | `api.cloudflare.com/client/v4/ips` | live |
| Fastly | `api.fastly.com/public-ip-list` | fixture |
| Bunny CDN | `bunnycdn.com/api/system/edgeserverlist` (IPv4 and IPv6) | fixture |
| AWS CloudFront | `d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips` | fixture |
| Gcore CDN | `api.gcore.com/cdn/public-ip-list` | fixture |
| Imperva | `my.imperva.com/api/integration/v1/ips` | fixture |
| Akamai, Sucuri | no complete published list | not verifiable: shown as an allow-list, never guessed |

## Private access: mesh VPNs

| Component | How it is recognized | What it means in the report | Status |
|---|---|---|---|
| Tailscale | sources in 100.64.0.0/10 or fd7a:115c:a1e0::/48; world-open UDP 41641; `tailscale0` interface | admin ports reachable only through the mesh; the UDP port is not counted as exposure | live |
| Headscale, NetBird | the same CGNAT range (shown as "Mesh VPN"); NetBird's `wt0` interface | as above | fixture |
| WireGuard | world-open UDP 51820; `wg*` interfaces | as above | fixture |
| ZeroTier | world-open UDP 9993; `zt*` interfaces (its address ranges are user-defined, so they show as allow-list) | as above | fixture |

## No inbound port at all: tunnels

The best pattern is a server that accepts nothing from the Internet. The report counts these servers under **No public ingress** and names any tunnel agent seen.

| Agent | How it is recognized | Status |
|---|---|---|
| Cloudflare Tunnel (`cloudflared`) | running process in the host bundle, or a container image | fixture |
| ngrok, frp, Tailscale Serve/Funnel, NetBird, ZeroTier | running process in the host bundle, or a container image | fixture |

Without a host bundle, a server with no public ingress is still counted; the tunnel name is simply unknown.

## Inside the server (owner-run host bundle)

| Component | What it checks | Status |
|---|---|---|
| UFW | first-match rules per address family, interface-bound rules, defaults | fixture (modeled on a real host) |
| nftables | input-hook chains, policy, ports, sources, protocol and family matches | fixture |
| iptables (legacy) | INPUT policy and rules for hosts not using nftables | fixture |
| firewalld zones, CSF, custom chains | recognized as "unknown": related findings stay `needs_validation` | planned |
| Listeners (`ss`) | what listens on public, private, loopback, or mesh addresses | fixture |
| Docker | ports published past the host firewall, privileged containers, Docker socket and host mounts, dangerous capabilities | fixture (modeled on a real host) |
| sshd | password login, root password login, empty passwords | fixture |
| PostgreSQL `pg_hba.conf` | trust or password-without-TLS for remote clients, in first-match order | fixture |
| Redis | bind, protected mode, password or ACL | fixture |
| MySQL, MongoDB, Podman | not read from the host (network exposure is still checked from the API) | planned |

## Other sources you can add

| Source | How | What it checks | Status |
|---|---|---|---|
| Terraform | `--terraform` with `terraform show -json` (state or saved plan) | unmanaged or deleted resources, drifted settings, firewall sources, pending plan changes | fixture |
| Several projects | `snapshot --project`, then `merge` | cross-project trust, production mixed with other environments | live (merge), fixture (rules) |
| Hetzner Robot | `--robot` (webservice user) or a saved file | Robot firewall, sensitive ports, unfiltered IPv6, vSwitch coupling, keys | fixture |
| Object Storage | `--object-storage` (S3 keys) or a saved file | public ACLs, wildcard policies, versioning | fixture (signing matches AWS test vectors) |
| Kubernetes | `--k8s` with `kubectl get nodes,pods,services -A -o json` | NodePorts open on nodes, workloads with node access, CCM/CSI/k3s detection | fixture |
| Node exporter via Prometheus | `hetzner-audit metrics`, then `--node-metrics` | RAM and disk headroom for rightsizing | fixture |
| Console checklist | `hetzner-audit checklist`, then `--attestations` | 2FA, member roles, tokens, Robot login, S3 keys, recovery contacts | fixture |
| Vulnerability scanners | Trivy JSON as signals | known vulnerabilities in reachable workloads | fixture |

## What it does not see

- Application-level authentication and authorization (beyond `pg_hba` and Redis).
- Traffic that actually flows; the audit reads configuration, it does not observe packets.
- Invoices and discounts; costs are net catalog prices.
- Anything on providers other than Hetzner.

Something missing or wrong? Open an issue with the component and, ideally, an anonymized example.
