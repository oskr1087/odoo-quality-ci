import tempfile
import unittest
from pathlib import Path
from scripts.code_governance import scan


class CodeGovernanceTests(unittest.TestCase):
    def test_duplicate_method_is_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "models.py"
            path.write_text("class Example:\n    def write(self): pass\n    def write(self): pass\n")
            findings = scan(Path(directory))
            self.assertIn("DUPLICATE_METHOD", {f["rule"] for f in findings})

    def test_repeated_inheritance_is_review_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module = root / "demo"
            module.mkdir()
            (module / "__manifest__.py").write_text("{}")
            (module / "models.py").write_text(
                'class A:\n    _inherit = "res.partner"\nclass B:\n    _inherit = "res.partner"\n'
            )
            findings = scan(root)
            self.assertTrue(any(f["rule"] == "FRAGMENTED_MODEL_INHERITANCE" and f["severity"] == "review" for f in findings))

    def test_syntax_error_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "broken.py").write_text("def broken(\n")
            self.assertIn("PYTHON_PARSE_ERROR", {f["rule"] for f in scan(Path(directory))})


if __name__ == "__main__":
    unittest.main()
