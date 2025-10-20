#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cleanup() {
  local exit_code=$?
  if [[ -n "${API_PID:-}" ]]; then
    kill "$API_PID" 2>/dev/null || true
  fi
  if [[ -n "${MONITOR_PID:-}" ]]; then
    kill "$MONITOR_PID" 2>/dev/null || true
  fi
  if [[ -n "${UI_PID:-}" ]]; then
    kill "$UI_PID" 2>/dev/null || true
  fi
  exit "$exit_code"
}
trap cleanup EXIT

cd "$ROOT_DIR"

python api.py &
API_PID=$!

echo "Started api.py (PID: $API_PID)"

python3 main.py monitor -i eth0 -m models/iforest.joblib &
MONITOR_PID=$!

echo "Started main.py monitor (PID: $MONITOR_PID)"

cd "$ROOT_DIR/ui"
npm run dev &
UI_PID=$!

echo "Started ui dev server (PID: $UI_PID)"

echo "All services started. Press Ctrl+C to stop."

wait -n