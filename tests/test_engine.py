import json
import unittest
from pathlib import Path

from src.compliance_engine import evaluate

ROOT = Path(__file__).resolve().parents[1]


class ComplianceEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.identity = json.loads((ROOT / "data/sample/identity_evidence.json").read_text())
        cls.audit = json.loads((ROOT / "data/sample/audit_evidence.json").read_text())
        cls.mappings = json.loads((ROOT / "mappings/control_map.json").read_text())
        cls.findings = evaluate(cls.identity, cls.audit, cls.mappings)

    def test_four_checks_run(self):
        self.assertEqual(len(self.findings), 4)

    def test_demo_has_expected_failures(self):
        failed = {f.check_id for f in self.findings if f.status == "FAIL"}
        self.assertIn("authorized_account_status", failed)
        self.assertIn("privileged_least_privilege", failed)
        self.assertIn("privileged_mfa", failed)
        self.assertIn("audit_logging_retention", failed)

    def test_control_ids_are_present(self):
        for finding in self.findings:
            self.assertTrue(finding.cmmc)
            self.assertTrue(finding.nist_800_171_rev2)


if __name__ == "__main__":
    unittest.main()
