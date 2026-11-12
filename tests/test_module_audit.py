import tempfile
import unittest
from pathlib import Path
from scripts.module_audit import analyze


class ModuleAuditTests(unittest.TestCase):
    def test_circular_dependency(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for name, dep in (("alpha", "beta"), ("beta", "alpha")):
                addon = root / name
                addon.mkdir()
                (addon / "__init__.py").write_text("")
                (addon / "__manifest__.py").write_text(repr({"name": name, "depends": [dep]}))
            rules = {finding["rule"] for finding in analyze(root)}
            self.assertIn("CIRCULAR_ADDON_DEPENDENCY", rules)

    def test_empty_module_is_advisory(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            addon = root / "empty_addon"
            addon.mkdir()
            (addon / "__init__.py").write_text("")
            (addon / "__manifest__.py").write_text("{'name': 'Empty', 'depends': ['base']}")
            findings = analyze(root)
            self.assertTrue(any(f["rule"] == "POSSIBLY_EMPTY_MODULE" and f["severity"] == "review" for f in findings))


if __name__ == "__main__":
    unittest.main()
