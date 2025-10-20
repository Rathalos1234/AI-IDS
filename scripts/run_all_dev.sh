#!/usr/bin/env bash
set -euo pipefail

# Go to repo root
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# ---- Python env ----
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install --upgrade pip -q
if [ -f requirements.txt ]; then
  pip install -r requirements.txt -q
fi

# ---- UI deps ----
if [ ! -d "ui/node_modules" ]; then
  ( cd ui && npm i )
fi

# ---- Run API (Flask dev) ----
export PYTHONUNBUFFERED=1
export REQUIRE_AUTH="${REQUIRE_AUTH:-0}"

python api.py &
API_PID=$!

# ---- Run UI (Vite dev) ----
export API_BASE="${API_BASE:-http://127.0.0.1:5000}"
(
  cd ui
  npm run dev
) &
WEB_PID=$!

cleanup() {
  kill "$API_PID" "$WEB_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

wait
