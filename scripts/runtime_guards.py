#!/usr/bin/env python3
"""Odoo version-aware, deterministic checks for known installation blockers."""
import argparse
import ast
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

# Only include fields confirmed removed in Odoo 20; do not speculate on others.
REMOVED_FIELDS = {
    20: {"ir.actions.report": {"report_file"}},
}


def audit(root: Path, version: str) -> list[dict]:
    major = int(version.split(".", 1)[0])
    removed = REMOVED_FIELDS.get(major, {})
    findings = []
    for manifest in sorted(root.rglob("__manifest__.py")):
        module = manifest.parent
        if any(part.startswith(".") for part in module.relative_to(root).parts):
            continue
        try:
            data = ast.literal_eval(manifest.read_text(encoding="utf-8"))
            files = data.get("data", []) + data.get("demo", [])
        except (SyntaxError, ValueError, TypeError, AttributeError) as exc:
            findings.append({"module": module.name, "file": str(manifest.relative_to(root)),
                             "rule": "MANIFEST_PARSE", "detail": str(exc)})
            continue
        for relative in files:
            if not isinstance(relative, str) or not relative.endswith(".xml"):
                continue
            path = module / relative
            if not path.is_file():
                findings.append({"module": module.name, "file": str(path.relative_to(root)),
                                 "rule": "MISSING_XML", "detail": "Declared XML file is missing"})
                continue
            try:
                tree = ET.parse(path)
            except ET.ParseError as exc:
                findings.append({"module": module.name, "file": str(path.relative_to(root)),
                                 "rule": "INVALID_XML", "detail": str(exc)})
                continue
            for record in tree.iter("record"):
                model = record.get("model")
                forbidden = removed.get(model, set())
                for field in record.findall("field"):
                    if field.get("name") in forbidden:
                        findings.append({"module": module.name, "file": str(path.relative_to(root)),
                                         "rule": "REMOVED_MODEL_FIELD",
                                         "detail": f"Odoo {major}: {model}.{field.get('name')} is removed",
                                         "xml_id": record.get("id", "")})
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--odoo-version", default="20.0")
    parser.add_argument("--output", type=Path, default=Path("qa-report/runtime-guards.json"))
    args = parser.parse_args()
    findings = audit(args.root.resolve(), args.odoo_version)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"version": args.odoo_version, "findings": findings},
                                      indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for item in findings:
        print(f"::error file={item['file']}::{item['rule']}: {item['detail']}")
    print(f"Runtime compatibility guards: {len(findings)} issue(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
