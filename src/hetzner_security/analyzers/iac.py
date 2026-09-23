"""Terraform drift rules (``--terraform``): unmanaged resources, resources deleted outside
Terraform, attribute drift, and pending plan changes to security controls. Firewall source
drift is HETZ-IAC-001 in rules.py, fed by expectations the loader adds.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..graph import AttackGraph
from ..iac import SECURITY_CHANGE_TYPES
from ..models import Evidence, Finding, Severity, Snapshot
from .rules import _candidate

SECURITY_ATTRIBUTES = {"firewall_ids", "delete_protection", "rebuild_protection", "backups"}
REFERENCE = ["https://developer.hashicorp.com/terraform/tutorials/state/resource-drift"]


def _evidence(terraform: dict[str, Any], asset_id: str, observed: object, kind: str) -> Evidence:
    return Evidence("terraform", kind, asset_id, observed, str(terraform.get("source")))


def terraform_drift(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    terraform = snapshot.metadata.get("terraform")
    if not isinstance(terraform, dict):
        return []
    output: list[Finding] = []
    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in terraform.get("unmanaged", []):
        by_type[str(item["type"])].append(item)
    for asset_type, items in sorted(by_type.items()):
        output.append(
            _candidate(
                "HETZ-IAC-002",
                f"{len(items)} {asset_type.replace('_', ' ')}(s) exist in Hetzner but not in Terraform",
                Severity.MEDIUM if asset_type == "firewall" else Severity.LOW,
                0.85,
                [item["asset_id"] for item in items],
                f"Terraform manages {asset_type} resources, but these were created or imported elsewhere.",
                "Every resource of a Terraform-managed type is in state, or explicitly out of scope.",
                f"Not in state: {[item['name'] for item in items][:10]}.",
                [_evidence(terraform, item["asset_id"], item, "terraform_unmanaged") for item in items[:20]],
                ["console or CLI change", asset_type],
                ["The state file covers the whole project (not a partial workspace)."],
                "Manual resources escape review, and a later apply can conflict with or ignore them.",
                "Import them (`terraform import`) or label them as intentionally unmanaged.",
                REFERENCE,
                asset_type,
            )
        )
    for item in terraform.get("missing", []):
        output.append(
            _candidate(
                "HETZ-IAC-003",
                f"{item['address']} is in Terraform state but no longer exists",
                Severity.LOW,
                0.9,
                [],
                "The provider has no resource with the ID recorded in state.",
                "State matches the provider.",
                f"{item['asset_id']} not found in the snapshot.",
                [_evidence(terraform, item["asset_id"], item, "terraform_missing")],
                [str(item["address"])],
                ["The snapshot collected this resource type successfully."],
                "The next apply recreates the resource, possibly with settings nobody expects.",
                "Find out who deleted it, then `terraform state rm` or re-apply deliberately.",
                REFERENCE,
                str(item["address"]),
            )
        )
    for item in terraform.get("attribute_drift", []):
        attributes = item["attributes"]
        security = sorted(set(attributes) & SECURITY_ATTRIBUTES)
        output.append(
            _candidate(
                "HETZ-IAC-004",
                "Runtime settings differ from Terraform" + (f" ({', '.join(security)})" if security else ""),
                Severity.MEDIUM if security else Severity.LOW,
                0.93,
                [item["asset_id"]],
                f"{item['address']}: {sorted(attributes)} differ between state and the API.",
                "Runtime attributes equal the reviewed Terraform values.",
                "; ".join(f"{name}: declared {want!r}, observed {have!r}" for name, (want, have) in sorted(attributes.items())),
                [_evidence(terraform, item["asset_id"], item, "terraform_attribute_drift")],
                ["console or CLI change", item["asset_id"]],
                ["The state is current (refreshed recently)."],
                "A manual change bypassed review; the next apply silently reverts it or fails.",
                "Decide which side is right: update the Terraform code, or run `terraform apply` to restore it.",
                REFERENCE,
                ",".join(sorted(attributes)),
            )
        )
    risky = [
        change for change in terraform.get("pending_changes", [])
        if change.get("type") in SECURITY_CHANGE_TYPES
        and ("delete" in change.get("actions", []) or "update" in change.get("actions", []))
    ]
    if risky:
        output.append(
            _candidate(
                "HETZ-IAC-005",
                f"The saved plan changes {len(risky)} security-relevant resource(s)",
                Severity.INFO,
                0.95,
                [],
                "A saved Terraform plan updates or deletes firewalls, servers, networks, or load balancers.",
                "Security-relevant plan changes are reviewed before apply.",
                "; ".join(f"{change['address']}: {'/'.join(change['actions'])}" for change in risky[:10]),
                [_evidence(terraform, str(change["address"]), change, "terraform_plan_change") for change in risky[:20]],
                ["terraform apply"],
                ["The plan is applied as saved."],
                "Applying the plan can widen exposure or remove a server.",
                "Review the listed changes; run `hetzner-audit diff` on snapshots before and after apply.",
                ["https://developer.hashicorp.com/terraform/cli/commands/plan"],
            )
        )
    return output


IAC_RULES = (terraform_drift,)
