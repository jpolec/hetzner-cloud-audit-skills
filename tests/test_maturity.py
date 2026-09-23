from __future__ import annotations

import json
import unittest

from hetzner_security.analyzers import hunt
from hetzner_security.findings import render_markdown, render_sarif
from hetzner_security.maturity import rule_maturity
from hetzner_security.models import Asset, Snapshot


class MaturityTest(unittest.TestCase):
    def test_every_finding_says_how_its_rule_was_tested(self) -> None:
        self.assertEqual(rule_maturity("HETZ-NET-001"), "live")
        self.assertEqual(rule_maturity("HETZ-K8S-002"), "fixture")
        server = Asset("hcloud:server:1", "server", "web", {"public_ip": True, "firewall_attached": False, "inbound": []}, {}, "hcloud_api")
        bucket = Asset("s3:bucket:fsn1:b", "bucket", "b", {"acl": [{"grantee": "AllUsers", "permission": "READ"}], "versioning": "Enabled"}, {}, "object_storage_api")
        findings = hunt(Snapshot(assets=[server, bucket]))
        self.assertTrue(all("rule_maturity" in item.metadata for item in findings))
        text = render_markdown(findings, {}, {}, None)
        self.assertIn("on fixtures only", text)
        self.assertIn("on a live Hetzner project", text)
        properties = [result["properties"]["ruleMaturity"] for result in json.loads(render_sarif(findings))["runs"][0]["results"]]
        self.assertIn("fixture", properties)


if __name__ == "__main__":
    unittest.main()
