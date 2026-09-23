"""Change signals from the provider's action history (last 30 days).

History shows that something changed, not whether the change was intended, so every finding
here is `needs_validation`: the owner confirms it was them. Routine changes (rule edits, applies,
reboots) are only counted in the summary; `diff` measures whether rule edits widened exposure.
A protection change is reported only when the resource is unprotected now.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..graph import AttackGraph
from ..models import Evidence, Finding, Severity, Snapshot
from .rules import _candidate

# command -> (rule, title, base severity, why it matters)
WATCHED: dict[str, tuple[str, str, Severity, str]] = {
    "change_protection": ("HETZ-CHG-001", "Protection settings changed", Severity.LOW,
                          "Protection guards against accidental deletion or rebuild."),
    "disable_backup": ("HETZ-CHG-001", "Protection settings changed", Severity.LOW,
                       "Provider backups were switched off."),
    "remove_firewall": ("HETZ-CHG-002", "Firewall removed from a resource", Severity.LOW,
                        "A firewall was removed from a resource."),
    "change_dns_ptr": ("HETZ-CHG-003", "Reverse DNS changed", Severity.INFO,
                       "Reverse DNS affects mail reputation and host identity."),
    "enable_rescue": ("HETZ-CHG-004", "Root-level access action ran", Severity.MEDIUM,
                      "Rescue mode boots a system with root access to the disks."),
    "reset_password": ("HETZ-CHG-004", "Root-level access action ran", Severity.MEDIUM,
                       "The root password was reset through the API."),
    "request_console": ("HETZ-CHG-004", "Root-level access action ran", Severity.MEDIUM,
                        "A VNC console session was opened."),
    "attach_iso": ("HETZ-CHG-004", "Root-level access action ran", Severity.MEDIUM,
                   "An ISO attached to a server can boot a different system."),
    "rebuild_server": ("HETZ-CHG-004", "Root-level access action ran", Severity.MEDIUM,
                       "Rebuild replaces the disk from an image."),
}


def _now_state(snapshot: Snapshot, asset_id: str) -> dict[str, Any]:
    asset = snapshot.asset_map().get(asset_id)
    return asset.properties if asset else {}


def provider_action_history(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for signal in snapshot.signals:
        if signal.get("type") != "provider_action" or signal.get("command") not in WATCHED:
            continue
        rule_id = WATCHED[str(signal["command"])][0]
        for asset_id in signal.get("asset_ids") or []:
            grouped[(rule_id, str(asset_id))].append(signal)
    assets = snapshot.asset_map()
    output: list[Finding] = []
    for (rule_id, asset_id), actions in sorted(grouped.items()):
        actions.sort(key=lambda item: str(item.get("started")))
        first = WATCHED[str(actions[0]["command"])]
        severity = max((WATCHED[str(item["command"])][2] for item in actions), key=_rank)
        state = _now_state(snapshot, asset_id)
        protection = state.get("protection") or {}
        commands_seen = {str(item["command"]) for item in actions}
        now_off = rule_id == "HETZ-CHG-001" and (
            ("change_protection" in commands_seen and protection.get("delete") is False)
            or ("disable_backup" in commands_seen and state.get("backup_enabled") is False)
        )
        unprotected = rule_id == "HETZ-CHG-002" and state.get("firewall_attached") is False
        if rule_id == "HETZ-CHG-001" and not now_off:
            continue  # protection was changed but is on now
        if now_off or unprotected:
            severity = Severity.MEDIUM if severity in {Severity.INFO, Severity.LOW} else severity
        commands = sorted({str(item["command"]) for item in actions})
        name = assets[asset_id].name if asset_id in assets else asset_id
        output.append(
            _candidate(
                rule_id,
                first[1] + f" on {name}",
                severity,
                0.8,
                [asset_id] if asset_id in assets else [],
                f"{len(actions)} action(s) in the last 30 days: {', '.join(commands)}. " + first[3],
                "Every security-relevant change is planned and attributable.",
                f"Last: {actions[-1].get('command')} at {actions[-1].get('started')} ({actions[-1].get('status')})."
                + (" The resource is now unprotected." if now_off else "")
                + (" The server now has no Cloud Firewall." if unprotected else ""),
                [Evidence("hcloud_api", "provider_action", asset_id, item, "actions") for item in actions[-10:]],
                ["provider API token", str(actions[-1].get("command")), asset_id],
                ["A token or console user with write access performed the action."],
                "An unplanned change can remove a control or indicate a compromised token or console account.",
                "Confirm who made the change (Console → Security → Activity) and restore the control if it was not intended.",
                ["https://docs.hetzner.cloud/reference/cloud#actions"],
                asset_id,
            )
        )
    return [finding for finding in output if finding.assets]


def _rank(severity: Severity) -> int:
    return [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL].index(severity)


def change_summary(snapshot: Snapshot, days: int = 30) -> dict[str, Any]:
    """Counts of recent provider actions by command, for the audit summary."""
    counts: dict[str, int] = defaultdict(int)
    for signal in snapshot.signals:
        if signal.get("type") == "provider_action":
            counts[str(signal.get("command"))] += 1
    return {"window_days": days, "total": sum(counts.values()), "by_command": dict(sorted(counts.items(), key=lambda item: -item[1]))}


CHANGE_RULES = (provider_action_history,)
