# UI / Playwright E2E (Sprint 2)

## Prereqs
- Node 18+
- Install: `npm i -D @playwright/test && npx playwright install --with-deps`

## Configure
- `BASE_URL` → UI (e.g., `http://localhost:5173`)
- `API_URL` (optional) → API (e.g., `http://localhost:8000`)
- `ARTIFACT_DIR` defaults to `sprint_artifacts/ui`

## Run
```bash
export BASE_URL=http://localhost:5173
export ARTIFACT_DIR=sprint_artifacts/ui
npx playwright test -c tests/ui/playwright.config.ts
```

## Notes
- Tests assume `data-test` and `data-testid` attributes exist in the UI.
- Headless run saves screenshots/videos to `sprint_artifacts/ui/` and HTML to `playwright-report/`.
