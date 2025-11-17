# UI Integration Tests (Playwright)

End-to-end UI checks live in `tests/ui/integration.s3.spec.ts`. They drive the browser, hit your **frontend** and the **Flask API**, and save screenshots/artifacts.

## Prereqs

* Node.js ≥ 18
* Install Playwright deps (only once):

  ```bash
  npm i -D @playwright/test
  npx playwright install --with-deps
  ```

## Start the app (2 processes)

**A) Backend API (Flask, same repo)**

* Easiest: start the embedded API by running monitor in simulate mode:

  ```bash
  export API_HOST=127.0.0.1 API_PORT=5000
  python3 api.py
  ```

**B) Frontend**

* Start your UI dev server (replace with your actual command/port):

  ```bash
  npm run dev  # e.g., http://localhost:5173
  ```

> Make sure your Playwright config’s `use.baseURL` targets the UI (e.g., `http://localhost:5173`). The tests navigate with hash routes like `/#/dashboard`.

## Run the tests

**Headless (CI-like)**

```bash
ARTIFACT_DIR="sprint_artifacts/ui" \
API_URL="http://127.0.0.1:5000" \
npx playwright test tests/ui/integration.s3.spec.ts \
  --project=chromium \
  --reporter=html,line
```

**Headed (watch it run)**

```bash
API_URL="http://127.0.0.1:5000" \
npx playwright test tests/ui/integration.s3.spec.ts \
  --project=chromium --headed
```

**Run a single test by title**

```bash
npx playwright test -g "Alerts: CSV and JSON export return attachments"
```

**Record extra diagnostics (optional)**

```bash
npx playwright test --trace on --reporter=html
# or enable video/screenshots on failures:
npx playwright test --reporter=html --config=playwright.config.ts
```

## See results & artifacts

**HTML report**

```bash
npx playwright show-report
```

**Screenshots & downloads**

* Saved under `sprint_artifacts/ui/` by default (override with `ARTIFACT_DIR`).
* The report also embeds screenshots and any test attachments.

## Environment variables the suite understands

* `API_URL` — Base URL for backend API (defaults to same origin as the UI if omitted).
* `ARTIFACT_DIR` — Where screenshots land (default: `sprint_artifacts/ui`).
* `HASH` — Router hash string (defaults to `#`; you usually don’t need to set this).

## Troubleshooting

* **Login fails (403):** backend `/api/auth/login` must be reachable; default creds in tests are `admin/admin`.
* **No rows/devices:** the suite can trigger a scan, but ensure the API is running (simulate mode is fine).
* **No downloads:** the UI must implement CSV/JSON export buttons on Alerts/Logs; tests wait for Playwright’s `download` events.
