"""Owner-declared architecture policy loader and expectation adapter."""

from __future__ import annotations

import json
import tomllib
from copy import deepcopy
from pathlib import Path
from typing import Any

from .models import Snapshot


def load_policy(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if path.suffix.lower() == ".json":
        value = json.loads(raw)
    elif path.suffix.lower() in {".toml", ".tml"}:
        value = tomllib.loads(raw.decode("utf-8"))
    else:
        raise ValueError("policy must be JSON or TOML; YAML is intentionally not parsed without a safe dependency")
    if not isinstance(value, dict):
        raise ValueError("policy root must be an object")
    return value


def apply_policy(snapshot: Snapshot, policy: dict[str, Any], *, source: str) -> Snapshot:
    result = deepcopy(snapshot)
    environments = policy.get("environments", {})
    if isinstance(environments, dict):
        observed = {asset.labels.get("environment") for asset in snapshot.assets}
        observed.discard(None)
        for target, config in environments.items():
            if not isinstance(config, dict):
                continue
            allowed = config.get("may_receive_from", [])
            if not isinstance(allowed, list):
                continue
            result.expectations.append(
                {
                    "kind": "environment_policy",
                    "target_environment": str(target),
                    "allowed_sources": [str(item) for item in allowed],
                    "observed_environments": sorted(str(item) for item in observed),
                    "path": source,
                }
            )
    services = policy.get("services", {})
    if isinstance(services, dict):
        for service, config in services.items():
            if isinstance(config, dict) and config.get("public") is False:
                result.expectations.append(
                    {"kind": "service_public", "service": str(service), "public": False, "path": source}
                )
    ssh = policy.get("ssh", {})
    if isinstance(ssh, dict) and ssh.get("public") is False:
        result.expectations.append(
            {"kind": "service_public", "service": "ssh", "public": False, "path": source}
        )
    result.metadata["policy_source"] = source
    return result
