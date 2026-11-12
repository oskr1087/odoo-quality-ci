#!/usr/bin/env bash
set -Eeuo pipefail
mkdir -p runtime-logs
mapfile -t modules < <(find project -mindepth 2 -maxdepth 2 -name __manifest__.py -printf '%h\n' | sed 's|.*/||' | sort)
if [[ "${#modules[@]}" -eq 0 ]]; then
  echo "No root-level Odoo addons found" >&2
  exit 1
fi
joined="$(IFS=,; echo "${modules[*]}")"
addons="$(pwd)/project,$(pwd)/odoo/addons,$(pwd)/odoo/odoo/addons"
base=(python odoo/odoo-bin --addons-path="$addons" --database=quality_odoo --db_host="${PGHOST:-localhost}" --db_port="${PGPORT:-5432}" --db_user="${PGUSER:-odoo}" --db_password="${PGPASSWORD:-odoo}" --stop-after-init --without-demo=all --no-http --log-level=info)
echo "Installing: $joined"
"${base[@]}" --init="$joined" 2>&1 | tee runtime-logs/install.log
if [[ "${DO_TESTS:-false}" == "true" ]]; then
  echo "Running Odoo module tests: $joined"
  if [[ "${DO_COVERAGE:-false}" == "true" ]]; then
    python -m coverage run --branch --source="$(pwd)/project" odoo/odoo-bin --addons-path="$addons" --database=quality_odoo --db_host="${PGHOST:-localhost}" --db_port="${PGPORT:-5432}" --db_user="${PGUSER:-odoo}" --db_password="${PGPASSWORD:-odoo}" --stop-after-init --without-demo=all --no-http --log-level=info --test-enable --update="$joined" 2>&1 | tee runtime-logs/tests.log
    python -m coverage json -o runtime-logs/coverage.json
    python -m coverage report | tee runtime-logs/coverage-summary.txt
  else
    "${base[@]}" --test-enable --update="$joined" 2>&1 | tee runtime-logs/tests.log
  fi
fi
if [[ "${DO_UPGRADE:-false}" == "true" ]]; then
  echo "Updating: $joined"
  "${base[@]}" --update="$joined" 2>&1 | tee runtime-logs/update.log
fi
