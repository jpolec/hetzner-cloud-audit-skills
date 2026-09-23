# Network audit module

Use cloud inventory plus authorized host-firewall, socket, container-publication, and service-bind evidence. No packet scanning or remote connection attempts are allowed by default.

Map interfaces, subnets, routes, firewall direction/source/port, load-balancer listeners, published ports, host rules, and bind addresses into directed edges. Run `hetzner-audit network --input snapshot.json --verify`. Prove every path and list unknown hops.

Check public management/data exposure, missing controls on public hosts, lateral movement, and declared environment separation. An open provider rule alone is only a candidate; verify attachment and downstream controls. Return evidence per hop plus `confirmed`, `needs_validation`, or `rejected`.

Hetzner Cloud Firewalls do not filter private network traffic (https://docs.hetzner.com/cloud/firewalls/faq/). Every server attached to a private network can reach every port on every other member. Firewall rules whose sources are private CIDRs have no effect on that traffic. Only host firewalls and service authentication restrict lateral movement, so ask for host-firewall evidence before calling a private path blocked.
