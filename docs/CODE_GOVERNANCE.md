# Odoo code governance standard

## Principle
Preserve installed Odoo workflows, technical identifiers, models, fields, data, and addon boundaries. Prefer minimal changes and native Odoo mechanisms. Any structural or business-flow change requires a documented justification, impact assessment, tests, and a human reviewer.

## Enforceable automated checks
- Python syntax errors and duplicate method declarations inside the same class are errors.
- The existing static/runtime audits and quality gate remain enabled.
- New audit `code-governance.json` identifies potentially fragmented `_inherit` classes, commented-out code, manifest changes, removed module structure, changes to sensitive lifecycle methods, and PRs with more than 15 changed paths.
- Review findings are **not automatic rejection**: legitimate Odoo extensions and large migrations are possible.

## Recommended conventions
- Python: PEP 8, Black, Ruff, `snake_case` functions/fields, `PascalCase` classes, explicit imports; avoid unused imports, dead code and commented-out implementation.
- Odoo: meaningful `_name` and `_inherit`, stable XML IDs, `__manifest__.py`, `models/`, `views/`, `security/`, `data/`, `tests/` when applicable.
- XML: valid syntax, unique IDs, consistent indentation, no redundant inherited views.
- New addon: documented distinct responsibility, alternatives, dependencies and compatibility.
- No unauthorized workflow redesign, broad refactor, module split/merge, XML ID renaming or schema removal.
- Review duplicated business logic and dependencies rather than blindly deleting them.

## Human approval
Sensitive changes require a PR explanation: objective, why existing structure cannot be reused, affected models/flows, compatibility plan, tests and reviewer approval. GitHub CODEOWNERS and branch rules must enforce this separately; CI cannot authenticate approval from prose alone.

## Scope and limitations
This first governance scanner is intentionally conservative. It does not yet fully enforce Black/Ruff formatting, detect semantic code duplication, prove unused modules, or enforce human approval. Add these as incremental checks with baselines to avoid mass false positives in existing repositories.
