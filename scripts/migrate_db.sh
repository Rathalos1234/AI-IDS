#!/usr/bin/env bash
set -euo pipefail
source .venv/bin/activate 2>/dev/null || true
python - <<'PY'
import webdb
webdb.init()
print("OK: migrations applied via webdb.init()")
PY
