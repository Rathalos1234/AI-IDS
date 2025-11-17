#!/usr/bin/env bash
set -euo pipefail
python -V
echo "Installing test extras (if needed)..."
pip install -q pytest
echo "Running full test suite (all tests)"

export PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}"
mkdir -p sprint_artifacts

pytest -ra -vv --durations=10 | tee sprint_artifacts/pytest_full.txt