import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from scripts.style_audit import audit


class StyleAuditTests(unittest.TestCase):
    @patch("scripts.style_audit.subprocess.run")
    def test_invalid_xml(self, run):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "bad.xml").write_text("<odoo><record></odoo>")
            self.assertIn("INVALID_XML", {x["rule"] for x in audit(root, ["bad.xml"])})

    @patch("scripts.style_audit.subprocess.run")
    def test_invalid_manifest(self, run):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "__manifest__.py").write_text("{'name': 'Test', 'depends': 'base'}")
            self.assertIn("INVALID_MANIFEST_DEPENDS", {x["rule"] for x in audit(root, ["__manifest__.py"])})

    @patch("scripts.style_audit.subprocess.run")
    def test_python_naming(self, run):
        run.return_value.returncode = 0
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "model.py").write_text("def BadFunction():\n    pass\n")
            self.assertIn("PYTHON_FUNCTION_NAMING", {x["rule"] for x in audit(root, ["model.py"])})


if __name__ == "__main__":
    unittest.main()
