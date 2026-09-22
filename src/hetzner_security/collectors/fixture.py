"""Load normalized JSON evidence fixtures for tests, CI, and offline audits."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import Asset, Edge, Evidence, Snapshot


def load_snapshot(path: Path) -> Snapshot:
    raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    assets = [Asset(**item) for item in raw.get("assets", [])]
    edges: list[Edge] = []
    for item in raw.get("edges", []):
        values = dict(item)
        values["evidence"] = tuple(Evidence(**e) for e in values.get("evidence", []))
        edges.append(Edge(**values))
    return Snapshot(
        assets=assets,
        edges=edges,
        expectations=raw.get("expectations", []),
        signals=raw.get("signals", []),
        metadata=raw.get("metadata", {}),
    )

