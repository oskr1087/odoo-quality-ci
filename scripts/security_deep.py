#!/usr/bin/env python3
"""Conservative Odoo security review: findings are advisory, not proof of exploits."""
import argparse
import ast
import csv
import json
from pathlib import Path
import xml.etree.ElementTree as ET


def finding(path, root, rule, detail, line=1, severity="review"):
    return {"file": str(path.relative_to(root)), "line": line, "rule": rule,
            "severity": severity, "detail": detail}


def scan(root):
    result = []
    for manifest in sorted(root.rglob("__manifest__.py")):
        addon = manifest.parent
        if any(part.startswith(".") for part in addon.relative_to(root).parts):
            continue
        access = addon / "security" / "ir.model.access.csv"
        if access.exists():
            with access.open(newline="", encoding="utf-8-sig") as stream:
                for line, row in enumerate(csv.DictReader(stream), 2):
                    if row.get("group_id:id", "").strip():
                        continue
                    if any(row.get("perm_" + key, "0").strip() == "1"
                           for key in ("write", "create", "unlink")):
                        result.append(finding(access, root, "ACL_GLOBAL_MUTATION",
                                              "Global ACL grants mutation without group", line))
        for path in sorted(addon.rglob("*.xml")):
            try:
                tree = ET.parse(path)
            except ET.ParseError:
                continue  # Existing XML validation handles malformed documents.
            for rec in tree.iter("record"):
                if rec.get("model") != "ir.rule":
                    continue
                fields = {f.get("name"): f for f in rec.findall("field")}
                domain = fields.get("domain_force")
                groups = fields.get("groups")
                if domain is not None and (domain.text or "").strip() in ("[(1, '=', 1)]", "[(1,'=',1)]", "[]") and groups is None:
                    result.append(finding(path, root, "GLOBAL_PERMISSIVE_RULE",
                                          "Review unrestricted global record rule"))
        for path in sorted(addon.rglob("*.py")):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except (SyntaxError, UnicodeError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr == "sudo":
                        result.append(finding(path, root, "SUDO_REVIEW",
                                              "Review privilege elevation and input authorization", node.lineno))
                    if node.func.attr == "route":
                        kw = {k.arg: k.value for k in node.keywords}
                        auth = kw.get("auth")
                        if isinstance(auth, ast.Constant) and auth.value in ("public", "none"):
                            result.append(finding(path, root, "PUBLIC_ROUTE_REVIEW",
                                                  "Review public endpoint authorization and CSRF", node.lineno))
    return result


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, default=Path.cwd())
    p.add_argument("--output", type=Path, default=Path("audit-report/security-deep.json"))
    args = p.parse_args()
    root = args.root.resolve()
    results = scan(root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"findings": results}, indent=2) + "\n")
    for item in results:
        print(f"::warning file={item['file']},line={item['line']}::{item['rule']}")
    print(f"Security deep audit: {len(results)} advisory finding(s)")


if __name__ == "__main__":
    main()
