#!/usr/bin/env bash
set -euo pipefail

# Set LINT_STRICT=0 to run tests even if lint/type checks fail.
LINT_STRICT="${LINT_STRICT:-1}"

echo "Python version:"
python -V

echo "=== Ruff (lint) ==="
if command -v ruff >/dev/null 2>&1; then
  if [[ "$LINT_STRICT" == "1" ]]; then
    ruff check --fix .
    ruff format
  else
    ruff check --fix . || true
    ruff format || true
  fi
else
  echo "ruff not found, skipping."
fi

echo "=== mypy (type check) ==="
if command -v mypy >/dev/null 2>&1; then
  if [[ "$LINT_STRICT" == "1" ]]; then
    mypy --ignore-missing-imports anomaly_detector.py packet_processor.py main.py
  else
    mypy --ignore-missing-imports anomaly_detector.py packet_processor.py main.py || true
  fi
else
  echo "mypy not found, skipping."
fi

echo "=== pytest (unit tests) ==="
export PYTHONPATH="${PYTHONPATH:-$PWD}"
pytest -m "unit" -q
