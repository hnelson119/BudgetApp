#!/usr/bin/env sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python_path="$project_root/.venv/bin/python"

if [ ! -x "$python_path" ]; then
  echo "Virtual environment not found. Create .venv and install the development dependencies first." >&2
  exit 1
fi

cd "$project_root"
"$python_path" manage.py check --settings=config.settings.test
"$python_path" manage.py makemigrations --check --dry-run --settings=config.settings.test
"$python_path" -m ruff check .
"$python_path" -m ruff format --check .
"$python_path" -m mypy audit budgets core debts goals households identity imports ledger notifications periods reserves schedules spending
"$python_path" scripts/secret_scan.py
"$python_path" scripts/check_cryptographic_inventory.py
"$python_path" scripts/check_logging_inventory.py
"$python_path" scripts/check_sbom.py
"$python_path" scripts/check_client_technologies.py
"$python_path" scripts/check_output_encoding.py
"$python_path" scripts/check_template_safety.py
"$python_path" scripts/check_os_command_safety.py
"$python_path" scripts/check_format_string_safety.py
"$python_path" scripts/check_communication_inventory.py
"$python_path" scripts/check_data_classification.py
"$python_path" scripts/check_canonical_decoding.py
"$python_path" scripts/check_managed_runtime_safety.py
"$python_path" scripts/check_input_validation_policy.py
"$python_path" scripts/check_authorization_policy.py
"$python_path" scripts/check_context_sanitization.py
"$python_path" scripts/check_resource_demand_policy.py
"$python_path" scripts/check_password_hashing_policy.py
"$python_path" scripts/check_regex_safety.py
"$python_path" scripts/check_release_evidence.py
"$python_path" scripts/check_device_test_evidence.py
"$python_path" scripts/check_adversarial_test_evidence.py
"$python_path" -m bandit -q -c pyproject.toml -r \
  audit budgets config core debts deploy/pentest goals households identity imports ledger \
  notifications periods reserves schedules spending
"$python_path" -m coverage erase
"$python_path" -m coverage run -m pytest
"$python_path" -m coverage report
"$python_path" scripts/check_branch_coverage.py --fail-under 80
