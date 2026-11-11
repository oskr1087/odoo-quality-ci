import json
import tempfile
import unittest
from pathlib import Path
from scripts.quality_reporting import convert


class ReportingTests(unittest.TestCase):
    def test_sarif_severity_location_and_deduplication(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d)
            (folder / "security-deep.json").write_text(json.dumps({"findings": [
                {"rule": "SUDO_REVIEW", "file": "demo/models.py", "line": 9,
                 "severity": "review", "detail": "Check sudo"},
                {"rule": "SUDO_REVIEW", "file": "demo/other.py", "line": 2,
                 "severity": "warning", "detail": "Check sudo"}]}))
            sarif, counts = convert(folder)
            run = sarif["runs"][0]
            self.assertEqual(len(run["tool"]["driver"]["rules"]), 1)
            self.assertEqual(len(run["results"]), 2)
            self.assertEqual(counts, {"error": 0, "warning": 1, "note": 1})
            self.assertEqual(run["results"][0]["locations"][0]["physicalLocation"]
                             ["region"]["startLine"], 9)


if __name__ == "__main__":
    unittest.main()
