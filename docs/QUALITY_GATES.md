# Enterprise QA gate and coverage

Reusable workflow options:

- `enforce_gate: true`: enforce policy after static scans. Default is false to preserve existing consumers.
- `tests: true` and `coverage: true` with `runtime: true`: measure Python branch coverage for project addon source while running Odoo tests. Output: `runtime-logs/coverage.json` and `coverage-summary.txt` as artifacts. Coverage is informational in this release; no minimum percentage is enforced.

Optional repository policy `.odoo-qa-policy.json`:

```json
{
  "required_reports": ["security-critical.json", "security-deep.json", "runtime-guards.json"],
  "block_severities": ["critical", "error"],
  "block_rules": [],
  "max_findings": null
}
```

`block_rules` can include `REMOVED_XML_IDS` for stricter backward-compatibility enforcement. Be careful: static detections may require human triage.

The gate fails closed for missing required or invalid reports. A green workflow does not mean every advisory is resolved. The runtime coverage job measures executed Python lines and branches, not functional completeness. The gate and coverage currently run in separate jobs; coverage thresholds are not yet a blocking gate. Code Scanning publication, SQL benchmarks, multi-company functional fixtures, and historical metrics remain outstanding.
