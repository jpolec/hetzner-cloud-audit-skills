# v0.3.1 release notes

v0.3.1 comes from the first audit of a real 18-server Hetzner project. It adds a network map and fixes the defects that run exposed.

## Highlights

- `hetzner-audit map` renders the network as Markdown with a Mermaid diagram, a dependency-free SVG, or JSON. Firewall sources are grouped into Internet, Cloudflare, Tailscale, private-network, and allow-listed classes, and each server is colored by exposure. Public IP addresses are never printed.
- `HETZ-GOV-003` reports servers that run a deprecated Hetzner server type.
- Markdown audit and `path` output now show asset names instead of numeric provider IDs.
- The SVG map uses a light theme by default (`--theme dark` is available), and all README images share that style.
- The README leads with a map and an audit summary from the real project, with identifiers replaced.

## Fixed

- A public IP address was treated as permitted traffic when tracing paths. As a result, `ask "Can the Internet reach any database?"` reported private-network paths as Internet exposure. Only firewall `allows` edges now carry traffic, and `ask` reports indirect pivots through a publicly reachable host separately from direct exposure.

## Safety

No provider mutation, SSH, port scan, or automatic remediation was added. The map summarizes firewall intent, not host or application controls. It omits public IPs but still reveals topology, so keep real maps private.
