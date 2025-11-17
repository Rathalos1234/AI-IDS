# Running the Backend Tests (with common gotchas)

Two helper scripts live at the repo root:

* `scripts/test_fast.sh` — **PR gate**: lint (ruff), format-check (ruff), type-check (mypy), and **unit tests**.
* `scripts/test_full.sh` — **broader check**: unit **+ integration** tests, then a **perf snapshot**.

> Works on Linux/macOS. On Windows, use **WSL** or **Git Bash**.

---

## 0) One-time setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
# tools used by the scripts
pip install ruff mypy pytest
# optional for some integration tests
pip install scapy
```

---

## 1) Fast gate (lint + type + unit)

```bash
bash scripts/test_fast.sh
```

What it does:

* `ruff check .` and `ruff format --check .`
* `mypy` on `anomaly_detector.py`, `packet_processor.py`, `main.py`
* `pytest -m "unit"` (unit tests only)
* Artifacts: `sprint_artifacts/pytest_unit.txt`

### Important: “Would reformat” means tests did **not** run

If you see lines like:

```
Would reformat: api.py
Would reformat: main.py
...
```

that’s **Ruff’s format check** failing. With `set -e` and `LINT_STRICT=1` (default), the script **stops before mypy/pytest**. Fix one of these ways:

* **Auto-format, then re-run**

  ```bash
  ruff format .
  bash scripts/test_fast.sh
  ```

* **Allow tests to run even if formatting fails** (useful when you’re in a hurry)

  ```bash
  LINT_STRICT=0 bash scripts/test_fast.sh
  ```

* **Run tests directly**

  ```bash
  pytest -m unit -vv
  ```

---

## 2) Full suite (unit + integration + perf)

```bash
bash scripts/test_full.sh
```

What it does:

* Ensures `pytest` is installed
* `pytest -m "unit or integration"` (integration tests may `skip` if Scapy isn’t installed)
* Perf snapshot: `pytest -m perf -k 10k -s` (prints `rows/sec` line)
* Artifacts:

  * `sprint_artifacts/pytest_full.txt`
  * `sprint_artifacts/pytest_perf.txt`

---

## 3) Handy pytest invocations (direct)

Run just unit tests:

```bash
pytest -m unit -vv
```

Run just integration tests:

```bash
pytest -m integration -vv
```

Select tests by name:

```bash
pytest -k "engineer_features or iforest" -vv
```

Show skip reasons:

```bash
pytest -ra -q
```

---

## 4) Troubleshooting

* **Formatting keeps failing:** run `ruff format .` at the repo root. Consider adding a pre-commit hook to auto-fix on commit.
* **Type check failures:** to proceed anyway, use `LINT_STRICT=0` (fast gate only) while you fix types.
* **Scapy-optional tests:** some integration paths call `@pytest.importorskip("scapy")`. Without Scapy they’ll **skip** (OK for CI).
* **Permissions:** live capture paths may require root; unit tests don’t.
* **Perf guardrail:** perf output prints `rows/sec=... time=... peakMB=...`. Keep a screenshot/log in your sprint packet.
* **Artifacts folder:** script outputs are mirrored to `sprint_artifacts/` for easy collection.
