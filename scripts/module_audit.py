#!/usr/bin/env python3
"""Analyze addon boundaries, manifest dependencies and import cycles conservatively."""
import argparse
import ast
import json
from collections import defaultdict
from pathlib import Path


def analyze(root):
    findings = []
    modules = {}
    for manifest in root.rglob("__manifest__.py"):
        if any(part in {".git", ".venv", "venv", "audit-report", "node_modules"} for part in manifest.relative_to(root).parts):
            continue
        directory = manifest.parent
        name = directory.name
        try:
            data = ast.literal_eval(manifest.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("Manifest must be a dict")
        except (SyntaxError, ValueError, TypeError) as exc:
            findings.append({"rule": "INVALID_MANIFEST", "severity": "error", "file": str(manifest.relative_to(root)), "message": str(exc)})
            continue
        modules[name] = (directory, data)
    for name, (directory, data) in modules.items():
        rel = str(directory.relative_to(root))
        deps = data.get("depends", [])
        if not isinstance(deps, list) or not all(isinstance(d, str) for d in deps):
            findings.append({"rule": "INVALID_DEPENDENCIES", "severity": "error", "file": rel + "/__manifest__.py", "message": "depends must contain module names"})
            continue
        if name in deps:
            findings.append({"rule": "SELF_DEPENDENCY", "severity": "error", "file": rel + "/__manifest__.py", "message": "Addon depends on itself"})
        if not (directory / "__init__.py").exists():
            findings.append({"rule": "MISSING_ADDON_INIT", "severity": "review", "file": rel, "message": "Missing __init__.py"})
        source = [p for p in directory.rglob("*.py") if p.name not in {"__init__.py", "__manifest__.py"} and "tests" not in p.relative_to(directory).parts]
        if not source and not any((directory / folder).exists() for folder in ("views", "data", "security", "static", "report")):
            findings.append({"rule": "POSSIBLY_EMPTY_MODULE", "severity": "review", "file": rel, "message": "No functional source or resources detected"})
        for dep in deps:
            if dep in modules and name in modules[dep][1].get("depends", []):
                if name < dep:
                    findings.append({"rule": "CIRCULAR_ADDON_DEPENDENCY", "severity": "error", "file": rel + "/__manifest__.py", "message": f"Mutual dependency: {name} <-> {dep}"})
    graph = {name: [dep for dep in data.get("depends", []) if dep in modules] for name, (_, data) in modules.items() if isinstance(data.get("depends", []), list)}
    state = {}
    def visit(name, stack):
        state[name] = 1
        for dep in graph.get(name, []):
            if state.get(dep) == 1:
                cycle = stack[stack.index(dep):] + [dep]
                findings.append({"rule": "CIRCULAR_ADDON_DEPENDENCY", "severity": "error", "file": name, "message": " -> ".join(cycle)})
            elif state.get(dep) is None:
                visit(dep, stack + [dep])
        state[name] = 2
    for name in graph:
        if name not in state:
            visit(name, [name])
    unique = {(f["rule"], f["message"]): f for f in findings}
    return list(unique.values())


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, default=Path("."))
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    findings = analyze(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"findings": findings}, indent=2) + "\n")
    print(f"Addon structure: {len(findings)} findings")


if __name__ == "__main__":
    main()
