"""Controls no API exposes (console members, 2FA, token scopes): a guided checklist.

The agent or the owner walks through CHECKLIST in the Hetzner Console and records answers in a
small JSON file (``hetzner-audit checklist --template``). ``--attestations FILE`` turns "no"
answers into confirmed findings and "unknown" answers into needs_validation findings; every
finding cites the owner's attestation as its evidence.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Snapshot

# key, rule, severity, question, where to look (finding titles are in TITLES)
CHECKLIST: tuple[tuple[str, str, str, str, str], ...] = (
    ("console_2fa_all_members", "HETZ-ATT-001", "high",
     "Does every person with access to the account or its projects use two-factor authentication?",
     "Console → your account → Security; ask each project member to confirm theirs."),
    ("project_members_least_role", "HETZ-ATT-002", "medium",
     "Is every project member still needed, with the least role that works (Owner/Admin/Member/Restricted/Viewer)?",
     "Console → project → Security → Members."),
    ("api_tokens_reviewed", "HETZ-ATT-003", "medium",
     "Is every Read & Write API token in use, owned by someone, and not replaceable by a Read token?",
     "Console → project → Security → API tokens (compare with CI/Terraform/automation that uses them)."),
    ("robot_account_protected", "HETZ-ATT-004", "high",
     "Robot (dedicated servers): is 2FA on for the Robot login, and are webservice users limited to what automation needs?",
     "Robot → Settings → Webservice and app settings / Two-factor authentication."),
    ("object_storage_keys_scoped", "HETZ-ATT-005", "medium",
     "Object Storage: are S3 credentials per application, rotated, and removed when unused?",
     "Console → project → Security → S3 credentials."),
    ("storage_box_access_reviewed", "HETZ-ATT-006", "low",
     "Storage Boxes: are sub-accounts limited to the directories they need, with SSH keys instead of passwords?",
     "Console → Storage Boxes → sub-accounts."),
    ("account_recovery_current", "HETZ-ATT-007", "medium",
     "Are the account's contact email and phone current, and can more than one trusted person recover access?",
     "Console → account settings; Robot → Administration → Contact data."),
)


TITLES = {
    "console_2fa_all_members": "Two-factor authentication is not on for every account member",
    "project_members_least_role": "Project members or roles are broader than needed",
    "api_tokens_reviewed": "Read & Write API tokens are not reviewed",
    "robot_account_protected": "Robot login or webservice users are not protected",
    "object_storage_keys_scoped": "Object Storage credentials are not scoped or rotated",
    "storage_box_access_reviewed": "Storage Box sub-account access is not reviewed",
    "account_recovery_current": "Account recovery contacts are not current",
}


def template() -> dict[str, Any]:
    return {
        "answered_by": "",
        "date": "",
        "answers": {key: "unknown" for key, *_ in CHECKLIST},
        "notes": {key: "" for key, *_ in CHECKLIST},
        "_help": "Set each answer to true (yes, in place), false (no), or 'unknown'. Omit keys that do not apply.",
    }


def render_checklist_markdown() -> str:
    lines = ["# Console checklist (no API exposes these)", "",
             "Walk through each item with the account owner. Record answers with `hetzner-audit checklist --template > answers.json`,",
             "then run the audit with `--attestations answers.json`.", ""]
    for index, (key, rule, severity, question, where) in enumerate(CHECKLIST, start=1):
        lines += [f"{index}. **{question}**", f"   - Where: {where}", f"   - Key: `{key}` · if no: {rule} ({severity})", ""]
    return "\n".join(lines)


def load_attestations(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("answers"), dict):
        raise ValueError(f"{path} must contain an 'answers' object (see `hetzner-audit checklist --template`)")
    known = {key for key, *_ in CHECKLIST}
    unknown_keys = sorted(set(raw["answers"]) - known)
    if unknown_keys:
        raise ValueError(f"unknown checklist keys in {path}: {unknown_keys}")
    return raw


def apply_attestations(snapshot: Snapshot, raw: dict[str, Any], source: str) -> Snapshot:
    snapshot.metadata["attestations"] = {
        "source": source,
        "answered_by": raw.get("answered_by") or None,
        "date": raw.get("date") or None,
        "answers": raw["answers"],
        "notes": {key: value for key, value in (raw.get("notes") or {}).items() if value},
    }
    return snapshot
