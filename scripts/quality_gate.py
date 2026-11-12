#!/usr/bin/env python3
"""Policy-driven QA gate. Missing mandatory reports fail closed."""
import argparse
import json
import sys
from pathlib import Path

REPORTS = {
    "security-critical.json": "security",
    "security-deep.json": "security",
    "runtime-guards.json": "compatibility",
    "regressions.json": "regressions",
    "performance.json": "performance",
    "code-governance.json": "architecture",
    "style.json": "style",
    "modules.json": "architecture",
}
SEVERITY = {"critical": 4, "error": 4, "high": 3, "warning": 2, "medium": 2,
            "review": 1, "info": 0, "note": 0}


def evaluate(directory, policy):
    required = policy.get("required_reports", [])
    block = policy.get("block_severities", ["critical", "error"])
    threshold = min((SEVERITY[x] for x in block), default=999)
    fail_rules = set(policy.get("block_rules", []))
    findings, failures = [], []
    for name, category in REPORTS.items():
        file = directory / name
        if not file.exists():
            if name in required:
                failures.append(f"Required report missing: {name}")
            continue
        try:
            payload = json.loads(file.read_text(encoding="utf-8"))
            items = payload["findings"]
            if not isinstance(items, list):
                raise ValueError("findings must be an array")
        except (ValueError, KeyError, TypeError) as exc:
            failures.append(f"Invalid report {name}: {exc}")
            continue
        for item in items:
            if not isinstance(item, dict):
                failures.append(f"Invalid finding in {name}")
                continue
            rule = str(item.get("rule", "UNKNOWN"))
            severity = str(item.get("severity", "review")).lower()
            finding = {"report": name, "category": category, **item}
            findings.append(finding)
            if rule in fail_rules or SEVERITY.get(severity, 1) >= threshold:
                failures.append(f"{name}: {rule} ({severity})")
    max_findings = policy.get("max_findings")
    if max_findings is not None and len(findings) > max_findings:
        failures.append(f"Findings {len(findings)} exceed limit {max_findings}")
    return {"passed": not failures, "total_findings": len(findings),
            "failures": failures, "findings": findings}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, default=Path("audit-report"))
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--output", type=Path, default=Path("audit-report/quality-gate.json"))
    args = parser.parse_args()
    policy = json.loads(args.policy.read_text()) if args.policy and args.policy.exists() else {}
    result = evaluate(args.directory, policy)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Quality gate: {'PASS' if result['passed'] else 'FAIL'}; findings={result['total_findings']}")
    for failure in result["failures"]:
        print(f"::error::{failure}")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
