# Roadmap for runtime coverage and quality reporting

Implemented: advisory static ORM query-in-loop analysis, JSON findings and SARIF artifact.

Not implemented in this PR: measured SQL query counts, Python line coverage, GitHub Code Scanning upload, historical quality dashboards.

Why: native Odoo tests run in a separate runtime job, and a meaningful coverage metric needs a well-defined addons-only measurement scope. SARIF upload requires security-events: write and a separate permissions decision; it is not silently enabled. Do not interpret a green workflow as zero advisory findings.
