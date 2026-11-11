# QA runtime tests and reporting

The reusable workflow accepts `tests: true` to execute Odoo's `--test-enable` during a module update after installation. The runtime job currently supports Community only. Test logs are uploaded in `shared-odoo-runtime-logs`.

The audit job emits `audit-report/quality.sarif` (SARIF 2.1.0) and `quality-summary.md`. The SARIF file is available as a workflow artifact. **Uploading to GitHub Code Scanning is not yet enabled**; it requires repository permissions and may depend on GitHub plan and repository visibility.

Security and regression findings are currently advisory, not evidence of exploitable vulnerabilities. This change does not provide test coverage percentages or performance profiling yet. Enabling tests may increase runtime substantially.
