from __future__ import annotations

import datetime as dt
import io
import json
import unittest
import urllib.error
import urllib.parse
from typing import Any

from hetzner_security.analyzers import hunt
from hetzner_security.collectors.objectstorage import (
    ReadOnlyObjectStorageCollector,
    apply_object_storage,
    sign_v4,
)
from hetzner_security.models import Snapshot
from hetzner_security.verification import verify_all

# AWS documentation example credentials, split so secret scanners do not flag them.
AWS_KEY, AWS_SECRET = "AKIAIOSFODNN7" + "EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCY" + "EXAMPLEKEY"
NS = 'xmlns="http://s3.amazonaws.com/doc/2006-03-01/"'
PUBLIC_ACL = f"""<AccessControlPolicy {NS}><Owner><ID>p</ID></Owner><AccessControlList>
<Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>p</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant>
<Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group"><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>READ</Permission></Grant>
</AccessControlList></AccessControlPolicy>"""
PRIVATE_ACL = PUBLIC_ACL.split("<Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">")[0] + "</AccessControlList></AccessControlPolicy>"


class SignatureTest(unittest.TestCase):
    def test_matches_aws_documented_vectors(self) -> None:
        when = dt.datetime(2013, 5, 24, tzinfo=dt.UTC)
        cases = [
            ("https://examplebucket.s3.amazonaws.com/test.txt", {"Range": "bytes=0-9"}, "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"),
            ("https://examplebucket.s3.amazonaws.com/?lifecycle", None, "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"),
            ("https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J", None, "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"),
        ]
        for url, extra, expected in cases:
            headers = sign_v4("GET", url, "us-east-1", AWS_KEY, AWS_SECRET, when, extra)
            self.assertTrue(headers["authorization"].endswith(f"Signature={expected}"), url)


class _Response(io.BytesIO):
    status = 200

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        return None


class CollectorTest(unittest.TestCase):
    def _collect(self) -> dict[str, Any]:
        routes: dict[tuple[str, str, str, bool], tuple[int, str]] = {
            ("fsn1", "/", "", True): (200, f"<ListAllMyBucketsResult {NS}><Buckets><Bucket><Name>public-assets</Name></Bucket>"
                                          f"<Bucket><Name>backups</Name></Bucket></Buckets></ListAllMyBucketsResult>"),
            ("fsn1", "/public-assets", "acl=", True): (200, PUBLIC_ACL),
            ("fsn1", "/public-assets", "policy=", True): (404, "<Error><Code>NoSuchBucketPolicy</Code></Error>"),
            ("fsn1", "/public-assets", "versioning=", True): (200, f"<VersioningConfiguration {NS}/>"),
            ("fsn1", "/public-assets", "max-keys=1", False): (200, f"<ListBucketResult {NS}/>"),
            ("fsn1", "/backups", "acl=", True): (200, PRIVATE_ACL),
            ("fsn1", "/backups", "policy=", True): (200, json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": ["*"]},
                                                                                     "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "arn:aws:s3:::backups/*"}]})),
            ("fsn1", "/backups", "versioning=", True): (200, f"<VersioningConfiguration {NS}><Status>Enabled</Status></VersioningConfiguration>"),
            ("fsn1", "/backups", "max-keys=1", False): (403, "<Error><Code>AccessDenied</Code></Error>"),
        }

        def fake(request: Any, timeout: int = 0) -> _Response:
            self.assertEqual(request.get_method(), "GET")
            url = urllib.parse.urlsplit(request.full_url)
            signed = "Authorization" in request.headers or "authorization" in {key.lower() for key in request.headers}
            key = (url.netloc.split(".")[0], url.path, url.query, signed)
            if key not in routes:
                raise urllib.error.URLError("unreachable")
            status, body = routes[key]
            if status != 200:
                raise urllib.error.HTTPError(request.full_url, status, "err", None, io.BytesIO(body.encode()))  # type: ignore[arg-type]
            return _Response(body.encode())

        collector = ReadOnlyObjectStorageCollector("key", "secret", locations=("fsn1",), verify_public=True)  # noqa: S106
        collector._urlopen = fake
        return collector.fetch()

    def test_collect_and_rules(self) -> None:
        raw = self._collect()
        names = {bucket["name"]: bucket for bucket in raw["buckets"]}
        self.assertTrue(names["public-assets"]["anonymous_list"])
        self.assertEqual(names["backups"]["versioning"], "Enabled")
        snapshot = apply_object_storage(Snapshot(), raw)
        findings = verify_all(hunt(snapshot), snapshot)
        found = {(item.rule_id, item.assets[0].rsplit(":", 1)[-1]): item for item in findings}
        self.assertEqual(found[("HETZ-OBJ-001", "public-assets")].severity.value, "high")  # type: ignore[union-attr]
        self.assertEqual(found[("HETZ-OBJ-001", "public-assets")].status.value, "confirmed")
        write = found[("HETZ-OBJ-002", "backups")]
        self.assertEqual(write.status.value, "needs_validation")  # anonymous listing refused; objects may still be writable
        self.assertIn(("HETZ-OBJ-003", "public-assets"), found)
        self.assertNotIn(("HETZ-OBJ-003", "backups"), found)

    def test_xml_with_dtd_is_refused(self) -> None:
        from hetzner_security.collectors.objectstorage import ObjectStorageError, _xml

        with self.assertRaises(ObjectStorageError):
            _xml(b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>')


if __name__ == "__main__":
    unittest.main()
