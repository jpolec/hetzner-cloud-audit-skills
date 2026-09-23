"""Findings from the owner's console checklist answers (``--attestations``)."""

from __future__ import annotations

from ..attestations import CHECKLIST, TITLES
from ..graph import AttackGraph
from ..models import Evidence, Finding, Severity, Snapshot
from .rules import _candidate


def console_attestations(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    attestations = snapshot.metadata.get("attestations")
    if not isinstance(attestations, dict):
        return []
    answers = attestations.get("answers") or {}
    notes = attestations.get("notes") or {}
    output: list[Finding] = []
    for key, rule_id, severity, question, where in CHECKLIST:
        answer = answers.get(key)
        if answer is True or key not in answers:
            continue
        unknown = answer is not False  # only a literal false is a definite "no"
        output.append(
            _candidate(
                rule_id,
                ("Not verified yet: " if unknown else "") + TITLES[key],
                Severity(severity),
                0.7 if unknown else 0.9,
                [],
                f"Owner answer: {answer!r}" + (f" ({notes[key]})" if notes.get(key) else "") + ".",
                question.rstrip("?") + ".",
                f"answered by {attestations.get('answered_by') or 'unnamed'} on {attestations.get('date') or 'unknown date'}",
                [Evidence("owner_attestation", "owner_attestation", key, {"answer": answer, "note": notes.get(key)}, attestations.get("source"))],
                ["account access", key],
                [],
                "A console-level gap bypasses every technical control the API shows.",
                f"Fix it in the console: {where}",
                ["https://docs.hetzner.com/accounts-panel/accounts/two-factor-authentication/"],
                key,
            )
        )
    return output


ATTESTATION_RULES = (console_attestations,)
