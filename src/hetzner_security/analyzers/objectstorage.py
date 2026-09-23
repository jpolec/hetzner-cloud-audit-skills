"""Object Storage rules (``--object-storage``): public ACL grants, public bucket policies, and
buckets without versioning. An anonymous listing probe, when present, decides the status.
"""

from __future__ import annotations

from ..collectors.objectstorage import public_grants, public_statements
from ..graph import AttackGraph
from ..models import Finding, Severity, Snapshot
from .rules import _candidate, _evidence

WRITE_PERMISSIONS = {"WRITE", "WRITE_ACP", "FULL_CONTROL"}
REFERENCE = ["https://docs.hetzner.com/storage/object-storage/howto-protect-objects/"]


def _actions(statement: dict[str, object]) -> list[str]:
    value = statement.get("Action") or []
    return [str(item).lower() for item in (value if isinstance(value, list) else [value])]


def bucket_exposure(snapshot: Snapshot, graph: AttackGraph) -> list[Finding]:
    output: list[Finding] = []
    for bucket in snapshot.assets:
        if bucket.type != "bucket":
            continue
        props = bucket.properties
        grants = public_grants(props)
        if grants:
            write = [grant for grant in grants if grant.get("permission") in WRITE_PERMISSIONS]
            everyone = any(grant.get("grantee") == "AllUsers" for grant in grants)
            output.append(
                _candidate(
                    "HETZ-OBJ-001",
                    "Bucket ACL grants access to " + ("everyone" if everyone else "any authenticated S3 user"),
                    Severity.CRITICAL if write else Severity.HIGH,
                    0.95,
                    [bucket.id],
                    f"ACL grants: {[(grant['grantee'], grant['permission']) for grant in grants]}.",
                    "Buckets grant access only to the owning project; public objects use a narrow policy on a prefix.",
                    f"public grants {grants}; anonymous listing {props.get('anonymous_list')}",
                    [_evidence(bucket, "bucket_acl", grants, "properties.acl")],
                    ["internet", bucket.id],
                    [],
                    "Anyone can " + ("write, overwrite, or delete objects" if write else "list or read objects") + ".",
                    "Set the bucket ACL to private and serve public files through a policy on a dedicated prefix or bucket.",
                    REFERENCE,
                    "acl",
                )
            )
        statements = public_statements(props)
        if statements:
            actions = sorted({action for statement in statements for action in _actions(statement)})
            dangerous = [action for action in actions if action in {"s3:*", "*"} or action.startswith(("s3:put", "s3:delete", "s3:abort", "s3:restore"))]
            conditional = all(statement.get("Condition") for statement in statements)
            output.append(
                _candidate(
                    "HETZ-OBJ-002",
                    "Bucket policy allows anonymous " + ("writes" if dangerous else "reads"),
                    Severity.CRITICAL if dangerous else Severity.MEDIUM if conditional else Severity.HIGH,
                    0.9,
                    [bucket.id],
                    f"Policy statements with Principal '*': actions {actions}" + (" (with conditions)" if conditional else "") + ".",
                    "Anonymous access, if needed at all, is read-only and limited to a public prefix.",
                    f"{len(statements)} public statement(s); anonymous listing {props.get('anonymous_list')}",
                    [_evidence(bucket, "bucket_policy", statements, "properties.policy")],
                    ["internet", bucket.id],
                    ["The statement's conditions (if any) match the requester."] if conditional else [],
                    "Anyone can " + ("modify or delete data" if dangerous else "read the objects the policy covers") + ".",
                    "Remove the wildcard principal, or scope Resource to a public prefix and Action to s3:GetObject.",
                    REFERENCE,
                    "policy",
                )
            )
        if props.get("versioning") in {"Off", "Suspended"}:  # None: not read, so no claim
            output.append(
                _candidate(
                    "HETZ-OBJ-003",
                    "Bucket versioning is off",
                    Severity.LOW,
                    0.9,
                    [bucket.id],
                    f"Versioning status: {props.get('versioning') or 'never enabled'}.",
                    "Buckets with data you cannot recreate keep previous versions (and object lock for backups).",
                    f"versioning={props.get('versioning')}",
                    [_evidence(bucket, "bucket_versioning", props.get("versioning"), "properties.versioning")],
                    ["leaked key or bad deploy", bucket.id],
                    ["An overwrite or delete happens."],
                    "An overwrite, delete, or ransomware run with a leaked key cannot be undone.",
                    "Enable versioning with a lifecycle rule that expires old versions.",
                    ["https://docs.hetzner.com/storage/object-storage/howto-protect-objects/"],
                )
            )
    return output


OBJECT_STORAGE_RULES = (bucket_exposure,)
