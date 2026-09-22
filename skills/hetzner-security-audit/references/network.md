# Network audit module

Use cloud inventory plus authorized host-firewall, socket, container-publication, and service-bind evidence. No packet scanning or remote connection attempts are allowed by default.

Map interfaces, subnets, routes, firewall direction/source/port, load-balancer listeners, published ports, host rules, and bind addresses into directed edges. Run `hetzner-sec network --input snapshot.json --verify`. Prove every path and list unknown hops.

Check public management/data exposure, missing controls on public hosts, lateral movement, and declared environment separation. An open provider rule alone is only a candidate; verify attachment and downstream controls. Return evidence per hop plus `confirmed`, `needs_validation`, or `rejected`.

