#!/usr/bin/env python3
"""Advisory static security review for Odoo addons (not a penetration test)."""

import argparse
import ast
import collections
import csv
import json
import pathlib
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parents[1]
FINDINGS = []


def report(module, path, line, rule, detail, severity="review"):
    FINDINGS.append(
        {
            "module": module,
            "path": path.relative_to(ROOT).as_posix(),
            "line": line,
            "rule": rule,
            "severity": severity,
            "detail": detail,
        }
    )


def addon_dirs():
    return sorted(
        folder for folder in ROOT.iterdir()
        if folder.is_dir() and (folder / "__manifest__.py").is_file()
    )


def literal(node):
    try:
        return ast.literal_eval(node)
    except (TypeError, ValueError):
        return None


def keyword(call, name):
    return next((item.value for item in call.keywords if item.arg == name), None)


def inspect_python(module, path):
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (SyntaxError, UnicodeError):
        return  # Syntax checks are handled by the existing quality gate.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute):
            if func.attr == "sudo":
                report(module, path, node.lineno, "SEC-SUDO",
                       "Review elevated access, record ownership and company boundaries")
            if func.attr == "execute" and node.args:
                query = node.args[0]
                if isinstance(query, (ast.JoinedStr, ast.BinOp)):
                    report(module, path, node.lineno, "SEC-SQL",
                           "Dynamic SQL construction: ensure parameterized query and safe identifiers",
                           "high")
            if func.attr in {"search", "search_read", "read_group"}:
                receiver = func.value
                if isinstance(receiver, ast.Call) and isinstance(receiver.func, ast.Attribute):
                    if receiver.func.attr == "sudo":
                        report(module, path, node.lineno, "SEC-SUDO-SEARCH",
                               "Search executed with elevated access; verify domain isolation")
            if func.attr == "route":
                auth = literal(keyword(node, "auth"))
                csrf = literal(keyword(node, "csrf"))
                methods = literal(keyword(node, "methods"))
                if auth == "public":
                    report(module, path, node.lineno, "SEC-PUBLIC-ROUTE",
                           "Public controller route: review authorization and data exposure")
                if csrf is False and methods and any(
                    method.upper() in {"POST", "PUT", "PATCH", "DELETE"}
                    for method in methods if isinstance(method, str)
                ):
                    report(module, path, node.lineno, "SEC-CSRF",
                           "State-changing route disables CSRF: validate alternate authentication")
        if isinstance(func, ast.Name) and func.id in {"eval", "exec"}:
            report(module, path, node.lineno, "SEC-EVAL",
                   "Dynamic Python execution requires security review", "high")
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name.startswith("_"):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            if not isinstance(decorator.func, ast.Attribute):
                continue
            if decorator.func.attr == "route" and literal(keyword(decorator, "auth")) == "none":
                report(module, path, node.lineno, "SEC-NONE-ROUTE",
                       "Route bypasses database authentication; review carefully", "high")


def inspect_acl(module, path):
    try:
        with path.open(encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            required = {"id", "model_id:id", "group_id:id", "perm_read",
                        "perm_write", "perm_create", "perm_unlink"}
            if not required.issubset(reader.fieldnames or []):
                report(module, path, 1, "SEC-ACL-FORMAT", "Missing expected ACL columns")
                return
            for row_no, row in enumerate(reader, 2):
                group = (row.get("group_id:id") or "").strip()
                writes = any((row.get(field) or "").strip() == "1"
                             for field in ("perm_write", "perm_create", "perm_unlink"))
                if not group and writes:
                    report(module, path, row_no, "SEC-ACL-GLOBAL-WRITE",
                           f"ACL {row.get('id')} grants write/create/delete without group",
                           "high")
    except (OSError, UnicodeError, csv.Error) as exc:
        report(module, path, 1, "SEC-ACL-READ", str(exc))


def inspect_xml(module, path):
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, UnicodeError):
        return
    for record in root.iter("record"):
        if record.attrib.get("model") != "ir.rule":
            continue
        fields = {field.attrib.get("name"): field for field in record.findall("field")}
        domain = fields.get("domain_force")
        if domain is None:
            report(module, path, 1, "SEC-RULE-DOMAIN",
                   f"Record rule {record.attrib.get('id', '(unnamed)')} has no domain_force")
        elif (domain.text or "").strip() in {"[(1, '=', 1)]", "[]"}:
            report(module, path, 1, "SEC-RULE-ALL",
                   f"Record rule {record.attrib.get('id', '(unnamed)')} matches all records; review scope")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="audit-report/security.json")
    args = parser.parse_args()
    folders = addon_dirs()
    for folder in folders:
        for path in sorted(folder.rglob("*.py")):
            inspect_python(folder.name, path)
        for path in sorted((folder / "security").glob("ir.model.access.csv")):
            inspect_acl(folder.name, path)
        for path in sorted(folder.rglob("*.xml")):
            inspect_xml(folder.name, path)
    findings = sorted(FINDINGS, key=lambda x: (x["module"], x["path"], x["line"], x["rule"]))
    counts = dict(sorted(collections.Counter(item["rule"] for item in findings).items()))
    payload = {
        "modules": len(folders),
        "total": len(findings),
        "rules": counts,
        "findings": findings,
        "limitations": [
            "Static review only; does not validate Odoo runtime ACL or record rules.",
            "sudo() and public routes can be legitimate; manual review is required.",
            "Multi-company isolation requires database-backed tests with real users.",
            "SQL checks cover simple dynamic expressions, not all injection patterns.",
        ],
    }
    target = ROOT / args.output
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    summary = [
        "## Odoo security audit", "",
        f"Modules: {len(folders)} · Advisory findings: {len(findings)}", "",
        "| Rule | Findings |", "| --- | ---: |",
    ]
    summary.extend(f"| {rule} | {count} |" for rule, count in counts.items())
    summary.extend(["", "Review findings manually; no runtime security guarantee."])
    (target.parent / "security-summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    print("\n".join(summary))


if __name__ == "__main__":
    main()
