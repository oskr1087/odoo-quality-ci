import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.security_deep import scan
from scripts.regression_audit import compare


class SecurityAndRegressionTests(unittest.TestCase):
    def test_security_advisories(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            addon = root / "demo"
            (addon / "security").mkdir(parents=True)
            (addon / "__manifest__.py").write_text("{}")
            (addon / "security" / "ir.model.access.csv").write_text(
                "id,name,model_id:id,group_id:id,perm_read,perm_write,perm_create,perm_unlink\n"
                "a,a,model_demo,,1,1,0,0\n"
            )
            (addon / "controller.py").write_text(
                "def route(self):\n"
                "    self.sudo()\n"
                "    http.route('/x', auth='public')\n"
            )
            rules = {item["rule"] for item in scan(root)}
            self.assertEqual(rules, {"ACL_GLOBAL_MUTATION", "SUDO_REVIEW", "PUBLIC_ROUTE_REVIEW"})

    def test_git_regression_detects_deleted_xmlid_and_field(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            def git(*args):
                return subprocess.run(["git", "-C", str(root), *args],
                                      check=True, capture_output=True, text=True).stdout.strip()
            git("init")
            git("config", "user.email", "qa@example.org")
            git("config", "user.name", "QA")
            addon = root / "demo"
            addon.mkdir()
            (addon / "__manifest__.py").write_text("{}")
            (addon / "data.xml").write_text('<odoo><record id="old_id" model="res.partner"/></odoo>')
            (addon / "models.py").write_text(
                "class Example:\n"
                "    _name = 'x.demo'\n"
                "    old_field = fields.Char()\n"
            )
            git("add", ".")
            git("commit", "-m", "before")
            base = git("rev-parse", "HEAD")
            (addon / "data.xml").write_text("<odoo/>")
            (addon / "models.py").write_text(
                "class Example:\n"
                "    _name = 'x.demo'\n"
            )
            git("add", ".")
            git("commit", "-m", "after")
            rules = {f["rule"] for f in compare(root, base, "HEAD")}
            self.assertIn("REMOVED_XML_IDS", rules)
            self.assertIn("REMOVED_FIELDS", rules)


if __name__ == "__main__":
    unittest.main()
