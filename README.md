# AI-Powered IDS — Hybrid Signature + Anomaly Network Monitor

Minimal, reproducible backend for your capstone: **capture → engineer features → train IsolationForest → verify bundle → monitor live traffic**, with a small **SignatureEngine** for explainable hits. Runs natively or in Docker.

---

## Features

* **Train** from live packets and save a **versioned model bundle** (`.joblib`).

  * Supports **packet-limited** training (`-c N`) **or** **indefinite** training until you press **Ctrl+C**.
* **Verify** a bundle before use (`verify-model` prints version, trained_at, params, feature order, checksum).
* **Monitor** live traffic with structured **ANOMALY** lines (decision score → `low|medium|high`).
* **SignatureEngine** (feature-flagged): rules like `port-scan-suspected` and `inbound-sensitive-port` emit **SIGNATURE** hits.
* **Rolling Parquet** (optional): persist engineered rows for later retraining.
* **Linux firewall bridge**: when you block an address in the UI the backend applies the rule to `iptables`; monitoring can auto-block high-severity offenders.

> Canonical feature vector

```
protocol, packet_size_log, time_diff, dport, is_ephemeral_sport, unique_dports_15s, direction
```

---

## Quickstart (native)

**Requirements:** Python 3.10+, `pip`. Linux recommended for live capture.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Train a model

Packet-limited:

```bash
python3 main.py train -i <iface> -c 1000 -m models/iforest.joblib
```

Indefinite (press **Ctrl+C** to stop and train on what was captured):

```bash
python3 main.py train -i <iface> -m models/iforest.joblib --until-ctrl-c
# optional soft floor before training
python3 main.py train -i <iface> -m models/iforest.joblib --until-ctrl-c --min-packets 500
```

### Verify the saved bundle

```bash
python3 main.py verify-model -m models/iforest.joblib
```

### Monitor live traffic

```bash
# Live capture on an interface
python3 main.py monitor -i <iface> -m models/iforest.joblib

# Add --firewall-blocking to drop high-severity sources via iptables (requires root)
python3 main.py monitor -i <iface> -m models/iforest.joblib --firewall-blocking

# Or generate synthetic traffic without touching your NIC
python3 main.py monitor -i lo -m models/iforest.joblib --simulate-traffic
```

Startup banner includes model metadata + thresholds. Alerts look like:

```
ANOMALY: ts=... <src_ip> -> <dest_ip> proto=<n> size=<bytes> dport=<n> eph_sport=<0/1> unique_dports_15s=<n> direction=<in|out> score=<float> severity=<low|medium|high>
SIGNATURE: <name> severity=<sev> | <src> -> <dest> dport=<n> desc="..."
```

---

## Configuration (`config.ini`)

Common knobs (defaults are safe):

| Section      | Key                     | Example                | Notes                                             |
| ------------ | ----------------------- | ---------------------- | ------------------------------------------------- |
| `Monitoring` | `AlertThresholds`       | `-0.10, -0.05`         | Maps score to **high/medium/low**.                |
| `Monitoring` | `OnlineRetrainInterval` | `0` or `100`           | Retrain every *K* packets (0 = disabled).         |
| `Monitoring` | `FirewallBlocking`      | `false`                | Auto-block high severity anomalies.               |
| `Monitoring` | `SimulateTraffic`       | `false`                | Generate synthetic packets when monitoring.       |
| `Training`   | `SaveRollingParquet`    | `true`                 | Enable Parquet persistence of engineered rows.    |
| `Training`   | `RollingParquetPath`    | `data/rolling.parquet` | Path for engineered rows.                         |
| `Training`   | `UntilCtrlCWindow`      | `100000`               | Window size used for **--until-ctrl-c** training. |
| `Logging`    | `LogLevel`              | `INFO`                 | `DEBUG`/`INFO`/`WARNING`/`ERROR`.                 |
| `Logging`    | `EnableFileLogging`     | `true`                 | Writes `logs/anomalies.log`.                      |
| `Signatures` | `Enable`                | `true`                 | Master toggle for SignatureEngine.                |
| `Signatures` | `PortScanThreshold`     | `10`                   | Trigger level for `port-scan-suspected`.          |
| `Signatures` | `SensitivePorts`        | `22,23,2323,3389,5900` | Port set for `inbound-sensitive-port`.            |
| `Signatures` | `DedupSeconds`          | `5.0`                  | Rate-limit repeated signature hits.               |

> Tip: create the Parquet folder upfront: `mkdir -p $(dirname data/rolling.parquet)`.

---

## CLI Overview

```bash
python3 main.py --help
python3 main.py train --help
python3 main.py monitor --help
python3 main.py verify-model --help
```

### Train

```bash
# Packet-limited
python3 main.py train -i <iface> -c <packet_count> -m models/iforest.joblib

# Indefinite until Ctrl+C
python3 main.py train -i <iface> -m models/iforest.joblib --until-ctrl-c [--min-packets N]
```

### Verify

```bash
python3 main.py verify-model -m models/iforest.joblib
```

### Monitor

```bash
python3 main.py monitor -i <iface> -m models/iforest.joblib [--firewall-blocking] [--simulate-traffic]
```

### Backup

```bash
python3 main.py backup-db
```

### Retention

```bash
python3 main.py retention
```
---

## Traffic generator (Sprint 3 Ops)

Use `traffic_gen.py` to **create baseline traffic for training** and **out-of-norm bursts** to prove the detector fires. It can run for a fixed time or **indefinitely until you press Ctrl+C**.

### Why

* Build a realistic “normal” profile before monitoring.
* Trigger obvious anomalies/signatures on demand (e.g., port scans, UDP high-port bursts).
* All local by default; no root required.

### Quick start

**1) Generate baseline traffic (indefinitely), then train-until-Ctrl+C**

```bash
# Terminal A — benign baseline loop (safe: localhost only)
python traffic_gen.py normal --until-ctrl-c --local-only --pps 25

# Terminal B — capture while A runs; stop when ready
python main.py train -i <iface> -m models/iforest.joblib --until-ctrl-c
```

**2) Verify & monitor**

```bash
python main.py verify-model -m models/iforest.joblib
python main.py monitor -i <iface> -m models/iforest.joblib
```

**3) Trigger out-of-norm events (watch alerts pop)**

```bash
# Port scan loop (ONLY scan your own host/lab). Press Ctrl+C to stop.
python traffic_gen.py portscan --target 127.0.0.1 --ports 20-120 --rate 300 --until-ctrl-c --sleep 1.5

# Or UDP high-port burst loop
python traffic_gen.py udpburst --target 127.0.0.1 --count 800 --pps 400 --until-ctrl-c --sleep 1
```

### Commands & options

**Baseline (“normal”)**

```bash
python traffic_gen.py normal [--duration 120] [--pps 20] [--local-only | --allow-internet] [--http-port 8080] [--until-ctrl-c]
```

* Generates a benign mix: HTTP, DNS (UDP 53), NTP-like (UDP 123), and occasional HTTPS connects (if `--allow-internet`).
* `--until-ctrl-c` ignores `--duration` and runs until you stop it.

**Port scan (out-of-norm)**

```bash
python traffic_gen.py portscan --target 127.0.0.1 --ports 20-1024 --rate 250 [--until-ctrl-c] [--sleep 1.0]
```

* Rapid TCP connects across a port range (drives `unique_dports_15s` and signature hits).

**UDP high-port burst (out-of-norm)**

```bash
python traffic_gen.py udpburst --target 127.0.0.1 --count 1000 --pps 300 [--until-ctrl-c] [--sleep 1.0]
```

* Sends many UDP packets to random high ports (also inflates `unique_dports_15s`).

### Safety & etiquette

* **Only** target `127.0.0.1` or lab machines you own/administer.
* Keep `--local-only` for baseline unless you explicitly allow internet.
* This script sends modest traffic and **doesn’t** require sudo.

---

## SignatureEngine (Sprint-1)

* Rules are code callables evaluated on the latest engineered row + current window.
* Default rules:

  * `port-scan-suspected` *(high)* — `unique_dports_15s ≥ PortScanThreshold`
  * `inbound-sensitive-port` *(medium)* — `direction == 0` and `dport ∈ SensitivePorts`
* Severity → log level: `high→ERROR`, `medium→WARNING`, `low→INFO`.
* Optional dedup: once per `(rule, src, dest)` in `DedupSeconds`.

Design doc: **`docs/signature_engine.md`**

---

## Rolling Parquet (optional)

Enable in `config.ini`:

```ini
[Training]
SaveRollingParquet = true
RollingParquetPath = data/rolling.parquet
```

Run monitor for ~10–30s, then:

```bash
python3 - << 'PY'
import pandas as pd
print(pd.read_parquet('data/rolling.parquet').head())
PY
```

---

## Docker (optional)

Build & run a reproducible container:

```bash
docker build -t ai-ids:sprint1 .
docker run --rm -it --net=host \
  -v "$PWD:/app" \
  ai-ids:sprint1 python main.py --help
```

> Use `--net=host` for live capture on Linux. You may need `--cap-add=NET_ADMIN` for firewall actions.

---

## Continuous integration

All pull requests and pushes run a fast gate mirroring `test_fast.sh` (ruff/black/mypy + unit tests). A fuller suite runs on push/nightly (unit + integration + perf). See `.github/workflows/`.

---

## Troubleshooting

* **Permission denied / no packets captured:** run with elevated privileges for live capture.
* **Firewall block errors:** `iptables` needs root; without it, requests will log but not apply rules.
* **Parquet file missing:** ensure `SaveRollingParquet=true`, path exists, and `pyarrow` is installed; let monitor run 10–30s.
* **No SIGNATURE lines:** traffic may not match defaults; try a quick local scan (see **Traffic generator** above).

---

## Security & Privacy

* Logs contain network metadata (IPs/ports). No payloads are stored.
* Signature rules and thresholds are tunable; signature evaluation is non-fatal (errors are caught & skipped).

---

© 2025 AI-Powered IDS Capstone.
