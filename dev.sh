#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ ! -d ".venv" ]]; then python3 -m venv .venv; fi
source .venv/bin/activate
python3 -m pip install --upgrade pip
if [[ -f requirements.txt ]]; then python3 -m pip install -r requirements.txt; fi
python3 - <<'PY'
try:
    import flask, flask_cors  # noqa
except Exception:
    import sys, subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "Flask", "flask-cors"])
PY

pushd ui >/dev/null
if [[ ! -d node_modules ]]; then npm i; fi
popd >/dev/null

python3 api.py & API_PID=$!

(cd ui && npm run dev) & WEB_PID=$!

trap 'kill $API_PID $WEB_PID 2>/dev/null || true' EXIT
wait
