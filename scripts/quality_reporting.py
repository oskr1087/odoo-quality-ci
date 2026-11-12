#!/usr/bin/env python3
"""Convert advisory Odoo QA JSON findings to SARIF 2.1.0 and a readable summary."""
import argparse
import json
from pathlib import Path

FILES = ("architecture.json", "security.json", "security-critical.json",
         "security-deep.json", "runtime-guards.json", "regressions.json", "performance.json", "code-governance.json", "style.json")
LEVELS = {"error": "error", "critical": "error", "warning": "warning",
          "review": "note", "info": "note"}


def convert(directory):
    rules, results, counts = {}, [], {"error": 0, "warning": 0, "note": 0}
    for filename in FILES:
        path = directory / filename
        if not path.is_file():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        items = payload.get("findings", []) if isinstance(payload, dict) else []
        for item in items:
            if not isinstance(item, dict):
                continue
            rule = str(item.get("rule", "QA_REVIEW"))
            level = LEVELS.get(str(item.get("severity", "review")).lower(), "note")
            message = str(item.get("detail") or item.get("message") or item.get("identifier") or rule)
            rules.setdefault(rule, {"id": rule, "shortDescription": {"text": rule}})
            result = {"ruleId": rule, "level": level, "message": {"text": message}}
            filename = item.get("file") or item.get("path")
            if filename:
                try:
                    line = max(1, int(item.get("line") or 1))
                except (TypeError, ValueError):
                    line = 1
                result["locations"] = [{"physicalLocation": {
                    "artifactLocation": {"uri": str(filename).replace("\\", "/")},
                    "region": {"startLine": line}}}]
            results.append(result)
            counts[level] += 1
    sarif = {"version": "2.1.0", "$schema":
             "https://json.schemastore.org/sarif-2.1.0.json",
             "runs": [{"tool": {"driver": {"name": "Odoo Quality CI",
                                            "rules": list(rules.values())}},
                       "results": results}]}
    return sarif, counts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, default=Path("audit-report"))
    args = parser.parse_args()
    sarif, counts = convert(args.directory)
    args.directory.mkdir(parents=True, exist_ok=True)
    (args.directory / "quality.sarif").write_text(json.dumps(sarif, indent=2) + "\n")
    summary = ("## Odoo QA findings\n\n"
               "| Level | Findings |\n|---|---:|\n"
               + "".join(f"| {level} | {counts[level]} |\n"
                         for level in ("error", "warning", "note")))
    (args.directory / "quality-summary.md").write_text(summary)
    print(summary)


if __name__ == "__main__":
    main()
