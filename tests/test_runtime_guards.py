import tempfile
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

    def test_missing_declared_xml(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            module = root / "test_addon"
            module.mkdir()
            (module / "__manifest__.py").write_text("{'data': ['missing.xml']}")
            self.assertEqual(audit(root, "20.0")[0]["rule"], "MISSING_XML")


if __name__ == "__main__":
    unittest.main()
