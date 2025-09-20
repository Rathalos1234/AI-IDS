
# Runbooks (Sprint 1) — AI-Powered IDS
_Last updated: 2025-09-19 23:43_

These runbooks cover **Start / Health / Stop**, **Incident Response (triage)**, and **Known Issues** for the Sprint‑1 deployment of the IDS. Commands assume a Unix-like shell.

---

## 0) Prerequisites
- Python **3.10+**, virtual environment recommended.
- Install deps:
  ```bash
  python3 -m venv .venv && source .venv/bin/activate
  pip install -r requirements.txt
  ```
- Packet capture may require elevated privileges (e.g., `sudo`).

---

## 1) Start / Health / Stop

### 1.1 Train a baseline model (first run)
```bash
python3 main.py train --interface <iface> --count 1000 --model models/iforest.joblib
```
- Replace `<iface>` with your interface (e.g., `eth0`, `wlan0`).
- Expect a success message indicating the model bundle path.

### 1.2 Verify the model bundle (health check A)
```bash
python3 main.py verify-model --model models/iforest.joblib
```
**Expected output includes**: model version, `trained_at`, IsolationForest params, **feature count/order/checksum**. Keep a screenshot for audit.

### 1.3 Start live monitoring (start)
```bash
sudo python3 main.py monitor --interface <iface> --model models/iforest.joblib
```
**Startup banner should show**:
- `Model info` with timestamp and algorithm params
- `Feature order` (count & names)
- `Alert thresholds: high<=..., medium<=...`
- `Logging` mode (file/dir/prefix) and `online_retrain_interval`

### 1.4 Health checks (during run)
- **Alerts flowing**: monitor console prints anomaly lines periodically.
- **Logs persisted**:
  ```bash
  tail -n 10 logs/anomalies.log
  ```
- **Rolling parquet exists** (forensics/retrain):
  ```bash
  ls -lh data/rolling.parquet
  ```

### 1.5 Stop
- Stop with **Ctrl+C** in the monitor terminal.
- Confirm last log timestamp in `logs/anomalies.log` for audit.

---

## 2) Incident Response (Triage by Severity)

The monitor assigns a **decision score** (Isolation Forest; more negative = more anomalous) and maps it to **severity** using `Monitoring.AlertThresholds` from `config.ini`. **Default:** `high<=-0.10`, `medium<=-0.05`, else `low`.

### 2.1 What an anomaly line looks like
```
ANOMALY: ts=<...> <src_ip> -> <dest_ip> proto=<p> size=<n> dport=<n> eph_sport=<0|1> unique_dports_15s=<n> direction=<in|out> score=<x.xxx> severity=<low|medium|high>
```

### 2.2 SOP by severity
- **HIGH**
  1. **Contain**: isolate host/segment; if available, issue a block (see 2.3).
  2. **Collect evidence** (see 2.4) and notify on‑call/lead.
  3. **Document**: action, reason, time.
- **MEDIUM**
  1. Investigate: check repeated events by IP/port/time.
  2. Consider temporary block; tune thresholds if noisy.
  3. Record outcome.
- **LOW**
  - Observe; add to feedback set for future tuning/re‑train.

### 2.3 Block / Unblock workflow (Sprint‑1 options)
- **If a Ban List/UI exists**: use it to **Block** and later **Unblock**; include reason.
- **If no UI yet**: record the decision and (optionally) enforce at OS level for demo:
  ```bash
  # Record (simple CSV)
  echo "$(date -Is),BLOCK,192.168.1.50,reason=port-scan" >> ops/banlist_demo.csv
  tail -n 1 ops/banlist_demo.csv

  # Optional OS-level block (example using ufw):
  sudo ufw deny from 192.168.1.50
  sudo ufw status | grep 192.168.1.50
  ```

### 2.4 Evidence to collect (attach to ticket/incident note)
- **Console** anomaly line (or alert detail screenshot).
- **Log excerpt** around the event (±10 lines).
- **Rolling parquet** snapshot (copy of `data/rolling.parquet` or a filtered export).
- **Config values used** at the time (thresholds, contamination).

---

## 3) Known Issues & Workarounds

- **Permission denied / no packets**  
  Use `sudo` for live sniffing; verify interface is correct (`ip link`, `ifconfig`).

- **Interface validation fails**  
  Ensure the interface name exists on the host; if `netifaces` is missing, install deps via `requirements.txt`.

- **Scapy not installed**  
  Install from `requirements.txt`. If unavailable in CI, skip live-capture tests and run integration/unit suites only.

- **Parquet append problems**  
  If append fails, overwrite mode is acceptable for Sprint‑1. Ensure `data/` exists and you have write permissions.

- **Too few anomalies for screenshots**  
  Temporarily bump `IsolationForest.Contamination` to `0.15` in `config.ini` to force alerts, then revert to normal (e.g., `0.05`).

- **Container environment**  
  Build once to validate the runtime is reproducible:
  ```bash
  docker build -t ai-ids:dev .
  docker run --rm ai-ids:dev python main.py --help
  ```

---

## 4) Quick Reference (copy/paste)

```bash
# Train
python3 main.py train --interface <iface> --count 1000 --model models/iforest.joblib

# Verify
python3 main.py verify-model --model models/iforest.joblib

# Monitor
sudo python3 main.py monitor --interface <iface> --model models/iforest.joblib

# Logs
tail -f logs/anomalies.log

# Parquet
ls -lh data/rolling.parquet
```

---

## 5) Change Management & Tuning (Sprint‑1)

- **Primary knobs** in `config.ini`:
  - `IsolationForest.Contamination` (default `0.05`)
  - `Monitoring.AlertThresholds` (default `-0.10, -0.05`)
  - `Logging.EnableFileLogging=true`, `LogDirectory=logs`
  - `Training.SaveRollingParquet=true`, `RollingParquetPath=data/rolling.parquet`
- **When noisy**: relax sensitivity (less negative thresholds or lower contamination).
- **When missing obvious issues**: tighten sensitivity (more negative thresholds or slightly higher contamination).

---

## 6) Post‑Incident Template (paste into ticket)

- **Summary:** <what happened, when, where>
- **Severity:** High | Medium | Low — threshold values at time of alert: high<=..., medium<=...
- **Indicators:** src/dst IPs, protocol, dport, unique_dports_15s, score
- **Actions:** contain (block/unblock), notify, tune thresholds?
- **Evidence:** console line, log excerpt, parquet slice, config snapshot
- **Follow‑ups:** RCA needed? retraining data flagged? thresholds changed?