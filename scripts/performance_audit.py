#!/usr/bin/env python3
"""Conservative AST-based ORM performance hints, never a runtime benchmark."""
import argparse
import ast
import json
from pathlib import Path

ORM_METHODS = {"search", "search_count", "read_group", "mapped", "filtered"}


def inspect(path, root):
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeError):
        return []
    parents = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in ORM_METHODS:
            continue
        cursor = parents.get(node)
        while cursor is not None and not isinstance(cursor, (ast.For, ast.AsyncFor, ast.While,
                                                             ast.FunctionDef, ast.AsyncFunctionDef)):
            cursor = parents.get(cursor)
        if isinstance(cursor, (ast.For, ast.AsyncFor, ast.While)):
            findings.append({"file": str(path.relative_to(root)), "line": node.lineno,
                             "rule": "ORM_QUERY_IN_LOOP", "severity": "review",
                             "detail": f"Review {node.func.attr}() inside loop; potential N+1"})
    return findings


def scan(root):
    result = []
    for manifest in sorted(root.rglob("__manifest__.py")):
        addon = manifest.parent
        if any(p.startswith(".") for p in addon.relative_to(root).parts):
            continue
        for path in sorted(addon.rglob("*.py")):
            result.extend(inspect(path, root))
    return result


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, default=Path.cwd())
    p.add_argument("--output", type=Path, default=Path("audit-report/performance.json"))
    args = p.parse_args()
    results = scan(args.root.resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"findings": results}, indent=2) + "\n")
    for item in results:
        print(f"::warning file={item['file']},line={item['line']}::{item['rule']}")
    print(f"ORM performance review: {len(results)} finding(s)")


if __name__ == "__main__":
    main()
