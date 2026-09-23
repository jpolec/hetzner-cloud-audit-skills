"""Compare the bundled Cloudflare ranges with Cloudflare's published list (network access needed)."""

from __future__ import annotations

import ipaddress
import json
import sys
import urllib.request

from hetzner_security.topology import CLOUDFLARE_RANGES, CLOUDFLARE_RANGES_AS_OF


def main() -> int:
    request = urllib.request.Request(  # noqa: S310 -- fixed HTTPS URL
        "https://api.cloudflare.com/client/v4/ips",
        headers={"User-Agent": "hetzner-audit/cloudflare-ranges-check", "Accept": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310
        result = json.loads(response.read())["result"]
    live = {ipaddress.ip_network(value) for value in [*result["ipv4_cidrs"], *result["ipv6_cidrs"]]}
    bundled = set(CLOUDFLARE_RANGES)
    missing, extra = sorted(map(str, live - bundled)), sorted(map(str, bundled - live))
    print(f"bundled list as of {CLOUDFLARE_RANGES_AS_OF}: {len(bundled)} ranges; live: {len(live)}")
    if missing or extra:
        print("missing from bundle:", missing)
        print("no longer published:", extra)
        return 1
    print("up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
