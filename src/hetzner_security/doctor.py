"""Preflight checks for a live audit: token, API access, scope, tools, and report privacy.

The token value is never printed, logged, or returned. Every API call is a read-only GET
that asks for a single item per endpoint.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .collectors.hcloud import (
    COLLECTOR_VERSION,
    HETZNER_API_BASE,
    HETZNER_RESOURCE_ENDPOINTS,
    RESOURCE_ENDPOINTS,
    HCloudCollectionError,
    ReadOnlyHCloudCollector,
)

# probe(endpoint, base_url) -> response payload; raises HCloudCollectionError on failure.
Probe = Callable[[str, str | None], dict[str, Any]]
OPTIONAL_TOOLS = {
    "uvx": "runs the pinned CLI without installing it",
    "terraform": "`terraform show -json` feeds `--terraform` drift checks",
    "kubectl": "`kubectl get nodes,pods,services -A -o json` feeds `--k8s` correlation",
    "trivy": "optional vulnerability signals (`--no-external-tools` disables them)",
}
# Optional read-only sources and the environment variables they read (values never printed).
OPTIONAL_SOURCES = {
    "Hetzner Robot (--robot)": ("HROBOT_USER", "HROBOT_PASSWORD"),
    "Object Storage (--object-storage)": ("HETZNER_S3_ACCESS_KEY", "HETZNER_S3_SECRET_KEY"),
    "Prometheus (hetzner-audit metrics)": ("PROMETHEUS_TOKEN",),
}
SECRET_NAMES = ("HCLOUD_TOKEN", "HROBOT_PASSWORD", "HETZNER_S3_SECRET_KEY", "PROMETHEUS_TOKEN")
SCOPE_KINDS = ("server", "firewall", "network", "volume", "load_balancer", "primary_ip")


def _check(name: str, status: str, detail: str) -> dict[str, str]:
    return {"name": name, "status": status, "detail": detail}


def _default_probe(token: str) -> Probe:
    collector = ReadOnlyHCloudCollector(token)

    def probe(endpoint: str, base_url: str | None) -> dict[str, Any]:
        return collector._get_json(endpoint, {"per_page": 1}, base_url=base_url)

    return probe


def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[str] | None:
    if shutil.which("git") is None:
        return None
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=False)


def _report_location(report_dir: Path) -> dict[str, str]:
    directory = report_dir.resolve()
    inside = _git(["rev-parse", "--is-inside-work-tree"], directory) if directory.is_dir() else None
    if inside is None or inside.returncode != 0 or inside.stdout.strip() != "true":
        return _check("Report location", "ok", f"{directory} is outside any Git repository.")
    probe_file = directory / "audit.md"
    ignored = _git(["check-ignore", "-q", str(probe_file)], directory)
    if ignored is not None and ignored.returncode == 0:
        return _check("Report location", "ok", f"{directory} is inside a Git repository but ignored.")
    return _check(
        "Report location",
        "warn",
        f"{directory} is inside a Git repository and not ignored. Reports contain topology; "
        "write them to an ignored directory (for example add `_output/` to .gitignore) or outside the repository.",
    )


def _dotenv_leak(report_dir: Path) -> dict[str, str] | None:
    env_file = report_dir / ".env"
    try:
        text = env_file.read_text(errors="ignore") if env_file.is_file() else ""
        found = [name for name in SECRET_NAMES if name in text]
        if found:
            return _check(
                "Token storage",
                "warn",
                f"{env_file} mentions {', '.join(found)}. Keep credentials in a password manager or keychain, not in a file.",
            )
    except OSError:
        return None
    return None


def run_doctor(
    env: Mapping[str, str] | None = None,
    report_dir: Path | None = None,
    probe: Probe | None = None,
    which: Callable[[str], str | None] = shutil.which,
) -> dict[str, Any]:
    env = os.environ if env is None else env
    report_dir = report_dir or Path.cwd()
    checks: list[dict[str, str]] = []
    version = sys.version_info
    checks.append(
        _check(
            "Python",
            "ok" if version >= (3, 11) else "fail",
            f"{version.major}.{version.minor}.{version.micro}; hetzner-audit {COLLECTOR_VERSION}",
        )
    )
    token = env.get("HCLOUD_TOKEN", "")
    scope: dict[str, int] = {}
    endpoints: dict[str, str] = {}
    if not token:
        checks.append(
            _check(
                "Token",
                "fail",
                "HCLOUD_TOKEN is not set. Create a project token with Read permission and load it without echoing "
                "(see docs/token-setup.md). Offline commands with --input still work.",
            )
        )
    else:
        checks.append(_check("Token", "ok", "HCLOUD_TOKEN is set (value not shown)."))
        probe = probe or _default_probe(token)
        targets: list[tuple[str, str, str | None]] = [(kind, endpoint, None) for kind, endpoint in RESOURCE_ENDPOINTS.items()]
        targets += [(kind, endpoint, HETZNER_API_BASE) for kind, endpoint in HETZNER_RESOURCE_ENDPOINTS.items()]
        latencies: list[float] = []
        rejected = False
        for kind, endpoint, base_url in targets:
            started = time.monotonic()
            try:
                payload = probe(endpoint, base_url)
            except HCloudCollectionError as exc:
                if exc.status == 401:
                    rejected = True
                    break
                endpoints[kind] = {
                    403: "forbidden",
                    404: "unavailable",
                    429: "rate-limited",
                }.get(exc.status or 0, "error")
                continue
            latencies.append(time.monotonic() - started)
            endpoints[kind] = "ok"
            total = payload.get("meta", {}).get("pagination", {}).get("total_entries")
            if kind in SCOPE_KINDS and isinstance(total, int):
                scope[kind] = total
        if rejected:
            checks.append(_check("API access", "fail", "Hetzner rejected the token (HTTP 401): it is invalid, revoked, or for another API."))
        elif not latencies:
            checks.append(_check("API access", "fail", "No endpoint answered; check network access to api.hetzner.cloud."))
        else:
            median = sorted(latencies)[len(latencies) // 2] * 1000
            checks.append(_check("API access", "ok", f"api.hetzner.cloud answered read-only GETs (median {median:.0f} ms)."))
            failed = {kind: state for kind, state in endpoints.items() if state != "ok"}
            core_failed = [kind for kind in failed if kind in {"server", "firewall", "network"}]
            checks.append(
                _check(
                    "Endpoint coverage",
                    "fail" if core_failed else "warn" if failed else "ok",
                    f"{len(endpoints) - len(failed)}/{len(endpoints)} endpoints readable"
                    + (": " + ", ".join(f"{kind} {state}" for kind, state in sorted(failed.items())) if failed else "."),
                )
            )
            summary = ", ".join(f"{count} {kind.replace('_', ' ')}{'s' if count != 1 else ''}" for kind, count in scope.items())
            checks.append(
                _check(
                    "Project scope",
                    "info",
                    f"{summary or 'no resources'}. Tokens are project-bound: confirm this is the project you meant to audit.",
                )
            )
        checks.append(
            _check(
                "Token permission",
                "info",
                "Read vs Read & Write cannot be verified without a write request, which this tool never sends. "
                "Confirm Read in Hetzner Console.",
            )
        )
    for tool, purpose in OPTIONAL_TOOLS.items():
        found = which(tool)
        checks.append(_check(f"Tool: {tool}", "ok" if found else "info", f"{'found' if found else 'not found'}; {purpose}."))
    for source, names in OPTIONAL_SOURCES.items():
        present = [name for name in names if env.get(name)]
        checks.append(_check(
            f"Source: {source}", "ok" if len(present) == len(names) else "info",
            "credentials set (values not shown)" if len(present) == len(names)
            else f"not configured ({', '.join(names)}); optional, read-only, or pass a saved file",
        ))
    checks.append(_check(
        "Host evidence (--host-bundle)", "info",
        "optional: `hetzner-audit host-bundle > host-bundle.sh`, review it, run it on each server, pass the output",
    ))
    checks.append(_report_location(report_dir))
    leak = _dotenv_leak(report_dir)
    if leak:
        checks.append(leak)
    checks.append(
        _check(
            "Report privacy",
            "info",
            "Reports and snapshots contain server names, private IPs, labels, and topology. `map` omits public IPs; "
            "other outputs do not. Secrets and personal data are redacted.",
        )
    )
    status = "fail" if any(item["status"] == "fail" for item in checks) else "warn" if any(item["status"] == "warn" for item in checks) else "ok"
    return {"status": status, "checks": checks, "scope": scope, "endpoints": endpoints}


def render_doctor_markdown(result: dict[str, Any]) -> str:
    icon = {"ok": "✓", "warn": "!", "fail": "✗", "info": "·"}
    lines = [f"# hetzner-audit doctor: {result['status'].upper()}", ""]
    for item in result["checks"]:
        lines.append(f"- {icon[item['status']]} **{item['name']}** — {item['detail']}")
    lines.extend(["", "No token value was printed. Only read-only GET requests were sent."])
    return "\n".join(lines)
