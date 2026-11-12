#!/usr/bin/env python3
"""Changed-file Odoo style and module-layout audit. No automatic rewrites."""
import argparse
import ast
import json
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

SKIP = {".git", ".venv", "venv", "node_modules", "__pycache__", "audit-report"}
XML_ID = re.compile(r"^[a-z][a-z0-9_]*$")
SNAKE = re.compile(r"^_?[a-z][a-z0-9_]*$")


def audit(root, paths):
    findings = []
    def add(rule, severity, path, message, line=1):
        findings.append(dict(rule=rule, severity=severity, file=str(path), line=line, message=message))
    for rel in sorted(set(paths)):
        path = root / rel
        if not path.is_file() or SKIP.intersection(Path(rel).parts):
            continue
        if path.suffix == ".py":
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
            except (SyntaxError, UnicodeError) as exc:
                add("PYTHON_PARSE_ERROR", "error", rel, str(exc))
                continue
            if path.name != "__manifest__.py":
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not SNAKE.fullmatch(node.name) and not (node.name.startswith("__") and node.name.endswith("__")):
                        add("PYTHON_FUNCTION_NAMING", "review", rel, node.name, node.lineno)
                    if isinstance(node, ast.ClassDef) and not (node.name[:1].isupper() and "_" not in node.name):
                        add("PYTHON_CLASS_NAMING", "review", rel, node.name, node.lineno)
            else:
                try:
                    manifest = ast.literal_eval(tree.body[0].value)
                    if not isinstance(manifest, dict):
                        raise ValueError("manifest is not a dict")
                    if not isinstance(manifest.get("depends", []), list):
                        add("INVALID_MANIFEST_DEPENDS", "error", rel, "depends must be a list")
                    if not manifest.get("name"):
                        add("MISSING_MANIFEST_NAME", "review", rel, "Missing module name")
                except (ValueError, TypeError, IndexError, AttributeError, SyntaxError):
                    add("INVALID_MANIFEST", "error", rel, "Manifest must be a literal Python dictionary")
        elif path.suffix == ".xml":
            try:
                tree = ET.parse(path)
                for record in tree.iter():
                    identifier = record.attrib.get("id")
                    if identifier and not XML_ID.fullmatch(identifier):
                        add("XML_ID_NAMING", "review", rel, f"Review XML id: {identifier}")
            except ET.ParseError as exc:
                add("INVALID_XML", "error", rel, str(exc))
        elif path.name.endswith((".pyc", ".pyo")) or path.name in {".DS_Store"}:
            add("GENERATED_FILE_COMMITTED", "error", rel, "Generated file should not be committed")
    pyfiles = [str(root / rel) for rel in paths if rel.endswith(".py") and (root / rel).is_file() and not SKIP.intersection(Path(rel).parts)]
    if pyfiles:
        for tool, command, rule in [
            ("black", ["black", "--check", "--quiet", *pyfiles], "BLACK_FORMAT"),
            ("ruff", ["ruff", "check", "--select", "E4,E7,E9,F,I", "--output-format", "concise", *pyfiles], "RUFF_STYLE"),
        ]:
            try:
                result = subprocess.run(command, capture_output=True, text=True, check=False)
                if result.returncode:
                    add(rule, "review", "python", (result.stdout + result.stderr)[:3000] or f"{tool} failed")
            except FileNotFoundError:
                add("STYLE_TOOL_MISSING", "error", "python", f"{tool} not installed")
    return findings


def changed(root, base):
    if not base:
        return [str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()]
    result = subprocess.run(["git", "-C", str(root), "diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD"], capture_output=True, text=True, check=True)
    return result.stdout.splitlines()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, default=Path("."))
    p.add_argument("--base")
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        paths = changed(args.root, args.base)
    except subprocess.CalledProcessError:
        paths = []
        findings = [{"rule": "DIFF_UNAVAILABLE", "severity": "error", "message": "Cannot determine changed files"}]
    else:
        findings = audit(args.root, paths)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"findings": findings}, indent=2) + "\n")
    print(f"Style audit: {len(findings)} findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
