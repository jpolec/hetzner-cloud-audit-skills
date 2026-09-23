"""Load normalized JSON evidence fixtures for tests, CI, and offline audits."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..models import Asset, Edge, Evidence, Fact, Snapshot

# Hard limits against crafted or corrupted input; far above any real Hetzner project.
MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
MAX_ASSETS = 200_000
MAX_EDGES = 1_000_000


def load_snapshot(path: Path) -> Snapshot:
    size = path.stat().st_size
    if size > MAX_SNAPSHOT_BYTES:
        raise ValueError(f"snapshot {path} is {size} bytes; the limit is {MAX_SNAPSHOT_BYTES}")
    raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"snapshot {path} must be a JSON object")
    for key, limit in (("assets", MAX_ASSETS), ("edges", MAX_EDGES)):
        if len(raw.get(key, []) or []) > limit:
            raise ValueError(f"snapshot {path} has more than {limit} {key}")
    assets = [Asset(**item) for item in raw.get("assets", [])]
    edges: list[Edge] = []
    for item in raw.get("edges", []):
        values = dict(item)
        values["evidence"] = tuple(Evidence(**e) for e in values.get("evidence", []))
        edges.append(Edge(**values))
    return Snapshot(
        assets=assets,
        edges=edges,
        facts=[Fact(**item) for item in raw.get("facts", [])],
        expectations=raw.get("expectations", []),
        signals=raw.get("signals", []),
        metadata=raw.get("metadata", {}),
    )
