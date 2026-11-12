#!/usr/bin/env python3
"""Conservative Odoo code governance checks; advisory unless explicitly gated."""
import argparse
import ast
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path

SENSITIVE = {"create", "write", "unlink", "action_post", "button_validate", "action_confirm"}
EXCLUDED = {".git", ".venv", "venv", "__pycache__", "node_modules", "audit-report"}


def scan(root):
    findings = []
    inherited = defaultdict(list)
    for path in sorted(root.rglob("*.py")):
        if EXCLUDED.intersection(path.relative_to(root).parts):
            continue
        if path.name == "__manifest__.py":
            continue
        rel = str(path.relative_to(root))
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
        except (SyntaxError, UnicodeError) as exc:
            findings.append({"rule": "PYTHON_PARSE_ERROR", "severity": "error", "file": rel, "message": str(exc)})
            continue
        for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
            model = None
            for item in cls.body:
                if isinstance(item, ast.Assign):
                    if any(isinstance(t, ast.Name) and t.id == "_inherit" for t in item.targets):
                        if isinstance(item.value, ast.Constant) and isinstance(item.value.value, str):
                            model = item.value.value
            if model:
                module = next((p for p in path.relative_to(root).parts if (root / p / "__manifest__.py").exists()), "")
                inherited[(module, model)].append((rel, cls.lineno))
            methods = defaultdict(list)
            for item in cls.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    methods[item.name].append(item.lineno)
            for name, lines in methods.items():
                if len(lines) > 1:
                    findings.append({"rule": "DUPLICATE_METHOD", "severity": "error", "file": rel, "line": lines[-1], "message": f"{cls.name}.{name} declared {len(lines)} times"})
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines, 1):
            if re.match(r"^\s*#\s*(?:def |class |from |import |return |if |for )", line):
                findings.append({"rule": "COMMENTED_CODE", "severity": "review", "file": rel, "line": index, "message": "Possible commented-out code"})
    for (module, model), locations in inherited.items():
        if len(locations) > 1:
            findings.append({"rule": "FRAGMENTED_MODEL_INHERITANCE", "severity": "review", "file": locations[0][0], "line": locations[0][1], "message": f"{module}: {model} extended in {len(locations)} classes; review consolidation"})
    return findings


def changed_paths(root, base):
    result = subprocess.run(["git", "-C", str(root), "diff", "--name-status", f"{base}...HEAD"], capture_output=True, text=True, check=True)
    return [line.split("\t") for line in result.stdout.splitlines() if line]


def governance(root, base):
    findings = []
    if not base:
        return findings
    try:
        changes = changed_paths(root, base)
    except subprocess.CalledProcessError:
        return [{"rule": "DIFF_UNAVAILABLE", "severity": "review", "message": "Could not inspect PR base"}]
    for parts in changes:
        status = parts[0]
        path = parts[-1]
        if path.endswith("/__manifest__.py") or path == "__manifest__.py":
            findings.append({"rule": "MODULE_MANIFEST_CHANGE", "severity": "review", "file": path, "message": "Review new modules, dependencies and module metadata"})
        if status.startswith("D") and (path.endswith("/__manifest__.py") or path.endswith("/__init__.py")):
            findings.append({"rule": "MODULE_STRUCTURE_REMOVAL", "severity": "high", "file": path, "message": "Module structure removed"})
        if path.endswith(".py") and not path.startswith("tests/"):
            try:
                diff = subprocess.run(["git", "-C", str(root), "diff", "--unified=0", f"{base}...HEAD", "--", path], capture_output=True, text=True, check=True).stdout
                if any(re.match(r"^[+-]\s*def\s+" + re.escape(name) + r"\b", line) for line in diff.splitlines() if not line.startswith(("+++", "---")) for name in SENSITIVE):
                    findings.append({"rule": "SENSITIVE_METHOD_CHANGE", "severity": "review", "file": path, "message": "Review modified Odoo lifecycle or workflow method"})
            except subprocess.CalledProcessError:
                pass
    if len(changes) > 15:
        findings.append({"rule": "LARGE_CHANGESET", "severity": "review", "message": f"{len(changes)} changed paths; confirm scope"})
    return findings


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, default=Path("."))
    p.add_argument("--base")
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    findings = scan(args.root) + governance(args.root, args.base)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"findings": findings}, indent=2) + "\n")
    print(f"Odoo code governance: {len(findings)} findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
