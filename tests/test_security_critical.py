import tempfile
import unittest
from pathlib import Path
from scripts.security_critical import audit


class SecurityCriticalTests(unittest.TestCase):
    def test_find_dynamic_exec_and_sql_interpolation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            addon = root / "demo"
            addon.mkdir()
            (addon / "__manifest__.py").write_text("{}")
            (addon / "models.py").write_text(
                "def bad(self, name):\n"
                "    eval(name)\n"
                "    exec(name)\n"
                "    self.env.cr.execute(f'SELECT * FROM t WHERE name={name}')\n"
            )
            self.assertEqual({f["rule"] for f in audit(root)},
                             {"PY_UNSAFE_EVAL", "PY_DYNAMIC_EXEC", "SQL_INTERPOLATED_QUERY"})

    def test_safe_parameterized_sql(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            addon = root / "demo"
            addon.mkdir()
            (addon / "__manifest__.py").write_text("{}")
            (addon / "models.py").write_text(
                "def good(self, name):\n"
                "    self.env.cr.execute('SELECT * FROM t WHERE name=%s', (name,))\n"
            )
            self.assertEqual(audit(root), [])


if __name__ == "__main__":
    unittest.main()
