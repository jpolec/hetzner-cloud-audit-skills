"""How far each rule family has been tested: on a live Hetzner project, or on fixtures only.

Shown next to every finding, so a report never presents a fixture-only rule with the same weight as
one exercised against real accounts. Update when a family is run against a live project.
"""

from __future__ import annotations

# Rule families run against at least one live Hetzner project by the maintainer.
LIVE_FAMILIES = {"NET", "FW", "GOV", "STO", "BCP", "XLY", "CHG", "COST", "EGR", "IMG", "KEY"}


def rule_maturity(rule_id: str) -> str:
    """'live' or 'fixture' for a rule ID such as HETZ-NET-001."""
    parts = rule_id.split("-")
    family = parts[1] if len(parts) > 2 else ""
    return "live" if family in LIVE_FAMILIES else "fixture"
