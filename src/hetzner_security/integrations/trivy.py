"""Convert Trivy JSON results to neutral signals for later correlation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def parse_trivy(path: Path, asset_id: str) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    signals: list[dict[str, Any]] = []
    for result in payload.get("Results", []):
        for vulnerability in result.get("Vulnerabilities") or []:
            signals.append(
                {
                    "type": "vulnerability",
                    "scanner": "trivy",
                    "asset_id": asset_id,
                    "vulnerability_id": vulnerability.get("VulnerabilityID"),
                    "package": vulnerability.get("PkgName"),
                    "installed_version": vulnerability.get("InstalledVersion"),
                    "fixed_version": vulnerability.get("FixedVersion"),
                    "severity": vulnerability.get("Severity"),
                    "primary_url": vulnerability.get("PrimaryURL"),
                }
            )
    return signals

