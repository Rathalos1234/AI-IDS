#!/usr/bin/env bash
set -euo pipefail
ALERTS_DAYS="${1:-30}"
BLOCKS_DAYS="${2:-30}"
source .venv/bin/activate 2>/dev/null || true
python - <<PY
import webdb
print(webdb.prune_old(days_alerts=${ALERTS_DAYS}, days_blocks=${BLOCKS_DAYS}))
PY
