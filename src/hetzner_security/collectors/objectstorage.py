"""Read-only Hetzner Object Storage collector (S3 API): buckets, ACLs, policies, versioning.

Object Storage keys are created per project in the Cloud Console and are separate from the
Cloud API token. The client signs GET requests with AWS Signature V4 using the standard
library only. With ``verify_public`` (``--verify-public-buckets``), a bucket whose ACL or policy
looks public gets one anonymous GET (list one key) to confirm it. The same normalization reads a saved file (``--object-storage FILE``).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET  # noqa: S405 -- size-capped, DOCTYPE rejected, from the owner's endpoint
from typing import Any

from ..models import Asset, Snapshot

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
LOCATIONS = ("fsn1", "nbg1", "hel1")
ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTHENTICATED_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


class ObjectStorageError(RuntimeError):
    pass


def _hmac(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode(), hashlib.sha256).digest()


def sign_v4(
    method: str, url: str, region: str, access_key: str, secret_key: str, now: dt.datetime, extra_headers: dict[str, str] | None = None
) -> dict[str, str]:
    """AWS Signature V4 headers for a request with an empty body."""
    parsed = urllib.parse.urlsplit(url)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    headers = {"host": parsed.netloc, "x-amz-content-sha256": EMPTY_SHA256, "x-amz-date": amz_date}
    headers.update({key.lower(): value for key, value in (extra_headers or {}).items()})
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    canonical_query = "&".join(
        f"{urllib.parse.quote(key, safe='-_.~')}={urllib.parse.quote(value, safe='-_.~')}" for key, value in sorted(query)
    )
    signed = ";".join(sorted(headers))
    canonical = "\n".join([
        method,
        urllib.parse.quote(parsed.path or "/", safe="/-_.~"),
        canonical_query,
        "".join(f"{key}:{headers[key].strip()}\n" for key in sorted(headers)),
        signed,
        EMPTY_SHA256,
    ])
    scope = f"{date}/{region}/s3/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = _hmac(_hmac(_hmac(_hmac(f"AWS4{secret_key}".encode(), date), region), "s3"), "aws4_request")
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed}, Signature={signature}"
    headers.pop("host")
    return headers


def _xml(body: bytes) -> ET.Element:
    if len(body) > MAX_RESPONSE_BYTES or b"<!DOCTYPE" in body or b"<!ENTITY" in body:
        raise ObjectStorageError("refusing an oversized or DTD-bearing XML response")
    try:
        return ET.fromstring(body)  # noqa: S314 -- see _xml guard above
    except ET.ParseError as exc:
        raise ObjectStorageError(f"unexpected non-XML response ({body[:60]!r})") from exc


def _strip(tag: str) -> str:
    return tag.split("}", 1)[-1]


def _find_all(root: ET.Element, name: str) -> list[ET.Element]:
    return [item for item in root.iter() if _strip(item.tag) == name]


def _text(root: ET.Element, name: str) -> str | None:
    found = _find_all(root, name)
    return found[0].text if found else None


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


class ReadOnlyObjectStorageCollector:
    """GET-only S3 client for Hetzner Object Storage. Keys: HETZNER_S3_ACCESS_KEY / HETZNER_S3_SECRET_KEY."""

    def __init__(self, access_key: str | None = None, secret_key: str | None = None, locations: tuple[str, ...] = LOCATIONS,
                 *, verify_public: bool = False) -> None:
        self._access = access_key or os.environ.get("HETZNER_S3_ACCESS_KEY")
        self._secret = secret_key or os.environ.get("HETZNER_S3_SECRET_KEY")
        if not self._access or not self._secret:
            raise ObjectStorageError("HETZNER_S3_ACCESS_KEY and HETZNER_S3_SECRET_KEY are required")
        self.locations = locations
        # One unsigned GET per bucket that already looks public; off unless the owner asks for it.
        self.verify_public = verify_public
        self._urlopen: Any = urllib.request.urlopen
        self._now: Any = _utc_now

    def _get(self, location: str, path: str, query: str = "", *, signed: bool = True) -> tuple[int, bytes]:
        url = f"https://{location}.your-objectstorage.com{path}{'?' + query if query else ''}"
        headers = sign_v4("GET", url, location, str(self._access), str(self._secret), self._now()) if signed else {}
        request = urllib.request.Request(url, headers=headers, method="GET")  # noqa: S310 -- fixed HTTPS endpoint
        try:
            with self._urlopen(request, timeout=30) as response:
                return int(getattr(response, "status", 200)), response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(MAX_RESPONSE_BYTES + 1) if exc.fp else b""
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            raise ObjectStorageError(f"read-only GET failed for {location}{path}: {exc}") from exc

    def fetch(self) -> dict[str, Any]:
        buckets: list[dict[str, Any]] = []
        seen: set[str] = set()
        for location in self.locations:
            status, body = self._get(location, "/")
            if status != 200:
                continue
            for bucket in _find_all(_xml(body), "Bucket"):
                name = _text(bucket, "Name")
                if not name or name in seen:
                    continue
                # ListBuckets can return every bucket of the project; keep those that answer here.
                acl_status, acl_body = self._get(location, f"/{urllib.parse.quote(name)}", "acl=")
                if acl_status in {301, 307, 400} or acl_status >= 500:
                    continue
                seen.add(name)
                buckets.append(self._bucket(location, name, acl_status, acl_body))
        return {"buckets": buckets}

    def _bucket(self, location: str, name: str, acl_status: int, acl_body: bytes) -> dict[str, Any]:
        path = f"/{urllib.parse.quote(name)}"
        grants = []
        if acl_status == 200:
            for grant in _find_all(_xml(acl_body), "Grant"):
                uri = _text(grant, "URI")
                grantee = "AllUsers" if uri == ALL_USERS else "AuthenticatedUsers" if uri == AUTHENTICATED_USERS else "account"
                grants.append({"grantee": grantee, "permission": _text(grant, "Permission")})
        policy_status, policy_body = self._get(location, path, "policy=")
        try:
            policy = json.loads(policy_body) if policy_status == 200 and policy_body else None
        except json.JSONDecodeError as exc:
            raise ObjectStorageError(f"bucket {name}: policy is not JSON") from exc
        versioning_status, versioning_body = self._get(location, path, "versioning=")
        versioning = None
        if versioning_status == 200:
            # An empty VersioningConfiguration means versioning was never enabled.
            versioning = (_text(_xml(versioning_body), "Status") if versioning_body.strip() else None) or "Off"
        # 404 on ?policy means "no policy"; any other failure means the setting is unknown.
        reads = {"acl": acl_status == 200, "policy": policy_status in {200, 404}, "versioning": versioning_status == 200}
        record: dict[str, Any] = {"name": name, "location": location, "acl": grants if reads["acl"] else None,
                                  "policy": policy, "versioning": versioning, "reads": reads}
        if self.verify_public and _looks_public(record):
            anonymous_status, _ = self._get(location, path, "max-keys=1", signed=False)
            record["anonymous_list"] = anonymous_status == 200
        return record


def _looks_public(bucket: dict[str, Any]) -> bool:
    return bool(public_grants(bucket) or public_statements(bucket))


def public_grants(bucket: dict[str, Any]) -> list[dict[str, Any]]:
    return [grant for grant in bucket.get("acl") or [] if grant.get("grantee") in {"AllUsers", "AuthenticatedUsers"}]


def public_statements(bucket: dict[str, Any]) -> list[dict[str, Any]]:
    policy = bucket.get("policy")
    if not isinstance(policy, dict):
        return []
    statements = policy.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    output = []
    for statement in statements:
        principal = statement.get("Principal")
        aws = principal.get("AWS") if isinstance(principal, dict) else None
        # Allow + NotPrincipal grants everyone except the listed principals.
        wildcard = principal == "*" or aws == "*" or (isinstance(aws, list) and "*" in aws) or "NotPrincipal" in statement
        if statement.get("Effect") == "Allow" and wildcard:
            output.append(statement)
    return output


def load_object_storage_file(path: Any) -> dict[str, Any]:
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError(f"Object Storage file {path} is too large")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or not isinstance(raw.get("buckets"), list):
        raise ValueError(f"{path} must be {{'buckets': [...]}} as written by the live collector")
    return raw


def apply_object_storage(snapshot: Snapshot, raw: dict[str, Any]) -> Snapshot:
    for bucket in raw["buckets"]:
        snapshot.assets.append(
            Asset(f"s3:bucket:{bucket.get('location')}:{bucket.get('name')}", "bucket", str(bucket.get("name")), bucket, {}, "object_storage_api")
        )
    failed = [bucket.get("name") for bucket in raw["buckets"] if not all((bucket.get("reads") or {"ok": True}).values())]
    snapshot.metadata.setdefault("coverage", {})["bucket"] = {
        "status": "partial" if failed else "collected", "count": len(raw["buckets"]), **({"unreadable": failed} if failed else {}),
    }
    return snapshot
