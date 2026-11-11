import tempfile
import unittest
from pathlib import Path
from scripts.performance_audit import scan


class PerformanceTests(unittest.TestCase):
    def test_search_inside_loop(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            addon = root / "demo"
            addon.mkdir()
            (addon / "__manifest__.py").write_text("{}")
            (addon / "models.py").write_text(
                "def run(self, items):\n"
                "    for item in items:\n"
                "        self.env['res.partner'].search([('name', '=', item)])\n"
            )
            self.assertEqual(scan(root)[0]["rule"], "ORM_QUERY_IN_LOOP")

    def test_search_outside_loop(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            addon = root / "demo"
            addon.mkdir()
            (addon / "__manifest__.py").write_text("{}")
            (addon / "models.py").write_text(
                "def run(self):\n"
                "    self.env['res.partner'].search([])\n"
            )
            self.assertEqual(scan(root), [])


if __name__ == "__main__":
    unittest.main()
