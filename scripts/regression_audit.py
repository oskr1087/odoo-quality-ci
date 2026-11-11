#!/usr/bin/env python3
"""Compare addon public identifiers and ORM declarations between Git revisions."""
import argparse
import ast
import json
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

MODEL_ASSIGNMENTS = {"_name", "_inherit"}
FIELD_TYPES = {"Char", "Text", "Html", "Integer", "Float", "Monetary", "Boolean",
               "Date", "Datetime", "Binary", "Selection", "Many2one", "One2many",
               "Many2many", "Reference", "Json", "Properties", "PropertiesDefinition"}


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          text=True, capture_output=True).stdout


def snapshot(root, ref):
    paths = git(root, "ls-tree", "-r", "--name-only", ref).splitlines()
    addons = {p.split("/")[0] for p in paths if p.endswith("/__manifest__.py") and p.count("/") == 1}
    result = {"modules": set(addons), "xml_ids": set(), "models": set(), "fields": set()}
    for path in paths:
        module = path.split("/")[0]
        if module not in addons:
            continue
        if path.endswith(".xml"):
            try:
                content = git(root, "show", f"{ref}:{path}")
                tree = ET.fromstring(content)
            except (ET.ParseError, subprocess.CalledProcessError):
                continue
            for element in tree.iter():
                xmlid = element.get("id")
                if xmlid and element.tag in ("record", "template", "menuitem", "report"):
                    result["xml_ids"].add(f"{module}.{xmlid}")
        if not path.endswith(".py"):
            continue
        try:
            tree = ast.parse(git(root, "show", f"{ref}:{path}"))
        except (SyntaxError, subprocess.CalledProcessError):
            continue
        for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
            model_names = []
            for item in cls.body:
                if not isinstance(item, (ast.Assign, ast.AnnAssign)):
                    continue
                targets = item.targets if isinstance(item, ast.Assign) else [item.target]
                value = item.value
                names = [t.id for t in targets if isinstance(t, ast.Name)]
                if "_name" in names:
                    try:
                        v = ast.literal_eval(value)
                        if isinstance(v, str):
                            model_names = [v]
                    except (ValueError, TypeError):
                        pass
                if "_inherit" in names and not model_names:
                    try:
                        v = ast.literal_eval(value)
                        if isinstance(v, str):
                            model_names = [v]
                    except (ValueError, TypeError):
                        pass
            for model in model_names:
                result["models"].add(model)
                for item in cls.body:
                    if not isinstance(item, ast.Assign) or not isinstance(item.value, ast.Call):
                        continue
                    func = item.value.func
                    if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                            and func.value.id == "fields" and func.attr in FIELD_TYPES):
                        for target in item.targets:
                            if isinstance(target, ast.Name):
                                result["fields"].add(f"{model}.{target.id}")
    return result


def compare(root, base, head):
    before, after = snapshot(root, base), snapshot(root, head)
    return [{"rule": "REMOVED_" + key.upper(), "identifier": value, "severity": "review"}
            for key in ("modules", "xml_ids", "models", "fields")
            for value in sorted(before[key] - after[key])]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--root", type=Path, default=Path.cwd())
    p.add_argument("--base", required=True)
    p.add_argument("--head", default="HEAD")
    p.add_argument("--output", type=Path, default=Path("audit-report/regressions.json"))
    args = p.parse_args()
    findings = compare(args.root.resolve(), args.base, args.head)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"base": args.base, "head": args.head,
                                       "findings": findings}, indent=2) + "\n")
    for item in findings:
        print(f"::warning::{item['rule']}: {item['identifier']}")
    print(f"Regression audit: {len(findings)} potential breaking change(s)")


if __name__ == "__main__":
    main()
