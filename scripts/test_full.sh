#!/usr/bin/env bash
set -euo pipefail
python -V
echo "Installing test extras (if needed)..."
pip install -q pytest
echo "Running full test suite (unit + integration). Some tests may be skipped if scapy is not installed."

export PYTHONPATH="${PYTHONPATH:-$PWD}"
mkdir -p sprint_artifacts
pytest -m "unit or integration" -ra -vv --durations=10 | tee sprint_artifacts/pytest_full.txt

# Perf snapshot (prints rows/sec line)
pytest -m perf -k 10k -s | tee sprint_artifacts/pytest_perf.txt