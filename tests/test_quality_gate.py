import json
import tempfile
import unittest
from pathlib import Path
from scripts.quality_gate import evaluate


class GateTests(unittest.TestCase):
    def test_critical_finding_blocks(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "security-critical.json").write_text(json.dumps(
                {"findings": [{"rule": "SQL_INJECTION", "severity": "critical"}]}))
            result = evaluate(root, {"block_severities": ["critical", "error"]})
            self.assertFalse(result["passed"])
            self.assertEqual(result["total_findings"], 1)

    def test_advisory_does_not_block_by_default(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "performance.json").write_text(json.dumps(
                {"findings": [{"rule": "ORM_QUERY_IN_LOOP", "severity": "review"}]}))
            self.assertTrue(evaluate(root, {})["passed"])

    def test_missing_required_report_blocks(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(evaluate(Path(d), {"required_reports": ["runtime-guards.json"]})["passed"])

    def test_explicit_rule_blocks(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "regressions.json").write_text(json.dumps(
                {"findings": [{"rule": "REMOVED_XML_IDS", "severity": "review"}]}))
            self.assertFalse(evaluate(root, {"block_rules": ["REMOVED_XML_IDS"]})["passed"])


if __name__ == "__main__":
    unittest.main()
