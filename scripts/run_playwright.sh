#!/usr/bin/env bash
set -euo pipefail

# ---- Config ----
export BASE_URL="${BASE_URL:-http://localhost:5173}"
export ARTIFACT_DIR="${ARTIFACT_DIR:-sprint_artifacts/ui}"

mkdir -p "${ARTIFACT_DIR}"

# ---- Node deps (Playwright) ----
if ! command -v npx >/dev/null 2>&1; then
  echo "Please install Node.js (v18+) first." >&2
  exit 1
fi

npm i -D @playwright/test >/dev/null 2>&1 || true
npx playwright install --with-deps

# ---- Run E2E ----
npx playwright test -c tests/ui/playwright.config.ts

echo ""
echo "UI artifacts in: ${ARTIFACT_DIR}/ and playwright-report/"
