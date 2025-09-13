#!/usr/bin/env bash
set -euo pipefail
python -V
echo "Installing test extras (if needed)..."
pip install -q pytest
echo "Running full test suite (unit + integration). Some tests may be skipped if scapy is not installed."
export PYTHONPATH="${PYTHONPATH:-$PWD}"
pytest -m "unit or integration" -q