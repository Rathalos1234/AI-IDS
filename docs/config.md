
# Operational Config & Tuning Guide (Sprint 1)
_Last updated: 2025-09-19 23:48_

This guide documents runtime knobs in **config.ini**, suggested ranges, and **when to change them**. Keep this file in `ops/config.md` and link it in your capstone doc.

---

## 1) Quick summary — what you’ll tune first
- **Severity thresholds** (`Monitoring.AlertThresholds`): *decision score* cutoffs → `high` / `medium`. More negative = more anomalous.
- **Outlier expectation** (`IsolationForest.Contamination`): higher → more anomalies.
- **Logging** (`Logging.*`): enable file logs, set directory/prefix.
- **Forensics** (`Training.SaveRollingParquet`, `RollingParquetPath`): enable rolling parquet for exports/retrain.

---

## 2) Current defaults (from `config.ini`)
| Section | Key | Value |
|---|---|---|
| `IsolationForest` | `contamination` | `0.05` |
| `IsolationForest` | `nestimators` | `200` |
| `IsolationForest` | `randomstate` | `42` |
| `IsolationForest` | `defaultinterface` | `eth0` |
| `IsolationForest` | `defaultpacketcount` | `1000` |
| `IsolationForest` | `defaultwindowsize` | `500` |
| `IsolationForest` | `modelpath` | `models/iforest.joblib` |
| `Logging` | `enablefilelogging` | `true` |
| `Logging` | `logdirectory` | `logs` |
| `Logging` | `anomalylogprefix` | `anomalies` |
| `Logging` | `loglevel` | `INFO` |
| `Logging` | `defaultinterface` | `eth0` |
| `Logging` | `defaultpacketcount` | `1000` |
| `Logging` | `defaultwindowsize` | `500` |
| `Logging` | `modelpath` | `models/iforest.joblib` |
| `Monitoring` | `onlineretraininterval` | `0` |
| `Monitoring` | `alertthresholds` | `-0.10, -0.05` |
| `Monitoring` | `defaultinterface` | `eth0` |
| `Monitoring` | `defaultpacketcount` | `1000` |
| `Monitoring` | `defaultwindowsize` | `500` |
| `Monitoring` | `modelpath` | `models/iforest.joblib` |
| `Training` | `saverollingparquet` | `true` |
| `Training` | `rollingparquetpath` | `data/rolling.parquet` |
| `Training` | `defaultinterface` | `eth0` |
| `Training` | `defaultpacketcount` | `1000` |
| `Training` | `defaultwindowsize` | `500` |
| `Training` | `modelpath` | `models/iforest.joblib` |


> Tip: After edits, restart the monitor; the startup banner will echo thresholds, logging mode, and retrain interval so you can verify the config is in effect.

---

## 3) Tuning playbook (operational scenarios)

### 3.1 False‑positive flood (too many benign alerts)
- Relax sensitivity: make thresholds **less negative** (e.g., `-0.10,-0.05` → `-0.08,-0.03`).
- Or lower `IsolationForest.Contamination` (e.g., `0.05` → `0.03`).
- Record before/after alert rates in the ops log.

### 3.2 Missed obvious malicious behavior
- Tighten sensitivity: **more negative** thresholds (e.g., `-0.12,-0.06`).
- Or raise `Contamination` slightly (e.g., `0.05` → `0.07–0.10`) to surface more outliers.

### 3.3 Quiet demo environment (need screenshots)
- Temporarily set `Contamination=0.15` and use thresholds like `-0.05, -0.02` to ensure at least one anomaly log; revert after evidence is collected.

---

## 4) Logging & data

- **Enable file logging**: `Logging.EnableFileLogging=true`, set `LogDirectory=logs`, `AnomalyLogPrefix=anomalies`, `LogLevel=INFO`.
- **Tail logs**: `tail -f logs/anomalies.log`.
- **Parquet**: set `Training.SaveRollingParquet=true`, `Training.RollingParquetPath=data/rolling.parquet` and verify with `ls -lh data/rolling.parquet`.

---

## 5) Online retrain (Sprint‑1 suggestion)
Keep `Monitoring.OnlineRetrainInterval=0` for stability in Sprint‑1. You can demo the path quickly in a controlled run by setting it to a small number (e.g., `100`) and watching for a retrain log line; reset to `0` afterward.

---

## 6) Change management log (copy block into tickets)
```
[CONFIG CHANGE]
when: <YYYY-MM-DD HH:MM>
who: <operator>
reason: <noisy alerts | missed attack | demo>
before:
  thresholds: <high, medium>
  contamination: <val>
after:
  thresholds: <high, medium>
  contamination: <val>
impact: <alert rate before/after, any follow-ups>
```