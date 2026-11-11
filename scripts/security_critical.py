#!/usr/bin/env python3
"""High-confidence Odoo security checks; never execute inspected source."""
import argparse
import ast
import json
from pathlib import Path
import sys

SINKS = {"eval": "PY_UNSAFE_EVAL", "exec": "PY_DYNAMIC_EXEC"}
DANGEROUS_SQL = {"execute", "executemany"}


def _is_literal_sql(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    return isinstance(node, ast.JoinedStr)


def inspect_file(path, root):
    findings = []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeError) as exc:
        return [{"file": str(path.relative_to(root)), "line": getattr(exc, "lineno", 1),
                 "rule": "PY_PARSE_ERROR", "detail": str(exc)}]
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        rule = None
        if isinstance(node.func, ast.Name) and node.func.id in SINKS:
            rule = SINKS[node.func.id]
        elif (isinstance(node.func, ast.Attribute) and node.func.attr in DANGEROUS_SQL
              and node.args and isinstance(node.func.value, ast.Attribute)
              and node.func.value.attr == "cr" and isinstance(node.args[0], ast.JoinedStr)):
            rule = "SQL_INTERPOLATED_QUERY"
        if rule:
            findings.append({"file": str(path.relative_to(root)), "line": node.lineno,
                             "rule": rule, "detail": "Review unsafe dynamic execution or SQL interpolation"})
    return findings


def audit(root):
    findings = []
    for manifest in sorted(root.rglob("__manifest__.py")):
        module = manifest.parent
        if any(p.startswith(".") for p in module.relative_to(root).parts):
            continue
        for path in sorted(module.rglob("*.py")):
            if "__pycache__" not in path.parts:
                findings.extend(inspect_file(path, root))
    return findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, default=Path("audit-report/security-critical.json"))
    args = parser.parse_args()
    findings = audit(args.root.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"findings": findings}, indent=2) + "\n")
    for item in findings:
        print(f"::warning file={item['file']},line={item['line']}::{item['rule']}")
    print(f"Security critical pattern review: {len(findings)} finding(s)")
    return 0  # Advisory until precision is measured on real repositories.


if __name__ == "__main__":
    sys.exit(main())
