import tempfile
import json
import subprocess
import sys
import unittest
from pathlib import Path

from scripts.runtime_guards import audit


class RuntimeGuardsTests(unittest.TestCase):
    def test_removed_report_file_only_in_odoo20(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            module = root / "test_addon"
            module.mkdir()
            (module / "__manifest__.py").write_text("{'data': ['report.xml']}")
            (module / "report.xml").write_text(
                '<odoo><record id="r" model="ir.actions.report">'
                '<field name="report_file">demo</field></record></odoo>'
            )
            self.assertEqual(audit(root, "19.0"), [])
            findings = audit(root, "20.0")
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule"], "REMOVED_MODEL_FIELD")

    def test_cli_exit_status_and_json_report(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            module = root / "test_addon"
            module.mkdir()
            (module / "__manifest__.py").write_text("{'data': ['report.xml']}")
            (module / "report.xml").write_text(
                '<odoo><record id="r" model="ir.actions.report">'
                '<field name="report_file">demo</field></record></odoo>'
            )
            output = root / "report.json"
            script = Path(__file__).resolve().parents[1] / "scripts" / "runtime_guards.py"
            command = [sys.executable, str(script), "--root", str(root),
                       "--odoo-version", "20.0", "--output", str(output)]
            failure = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(failure.returncode, 1, failure.stderr)
            self.assertEqual(json.loads(output.read_text())["findings"][0]["rule"],
                             "REMOVED_MODEL_FIELD")
            command[command.index("20.0")] = "19.0"
            success = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(success.returncode, 0, success.stderr)

    def test_missing_declared_xml(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            module = root / "test_addon"
            module.mkdir()
            (module / "__manifest__.py").write_text("{'data': ['missing.xml']}")
            self.assertEqual(audit(root, "20.0")[0]["rule"], "MISSING_XML")


if __name__ == "__main__":
    unittest.main()
