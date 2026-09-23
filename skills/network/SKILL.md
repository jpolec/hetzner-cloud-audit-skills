---
name: hetzner-network-audit
description: Reconstruct Hetzner public/private reachability and environment segmentation for cross-layer security analysis.
---

# Hetzner Network Audit

Required inputs: cloud inventory plus any authorized host firewall, socket, container publication, and service bind evidence. No packet scanning or remote connection attempts are allowed by default.

Workflow: map interfaces, subnets, routes, firewall directions/sources/ports, load-balancer listeners, published container ports, host rules, and service bind addresses into directed edges. Run `hetzner-audit network --input snapshot.json --verify`. Prove each reported path from source to target and list unknown hops.

Check public SSH/management/database/cache exposure, missing controls on public hosts, broad lateral movement, and declared environment separation. An open provider rule alone is a candidate; verify attachment and downstream controls. Output an attack path with evidence per hop and one of `confirmed`, `needs_validation`, or `rejected`.

Hetzner Cloud Firewalls do not filter private network traffic (https://docs.hetzner.com/cloud/firewalls/faq/). Every server attached to a private network can reach every port on every other member. Firewall rules whose sources are private CIDRs have no effect on that traffic. Only host firewalls and service authentication restrict lateral movement, so ask for host-firewall evidence before calling a private path blocked.
