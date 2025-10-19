# AI-Powered IDS — Hybrid Signature + Anomaly Network Monitor

Minimal, reproducible backend for your capstone: **capture → engineer features → train IsolationForest → verify bundle → monitor live traffic**, with a small **SignatureEngine** for explainable hits. Runs natively or in Docker.

---

## Features

- **Train** from live packets and save a **versioned model bundle** (`.joblib`).
- **Verify** a bundle before use (`verify-model` prints version, trained_at, params, feature order, checksum).
- **Monitor** live traffic with structured **ANOMALY** lines (score → `low|medium|high`).
- **SignatureEngine** (feature-flagged): code-based rules like `port-scan-suspected` and `inbound-sensitive-port` emit **SIGNATURE** hits.
- **Rolling Parquet** (optional): persist engineered rows for later retraining.
- **Linux firewall bridge**: when you block an address in the UI the backend applies the rule to `iptables`, and monitoring can auto-block high-severity offenders.

> Canonical feature vector:

```
protocol, packet_size_log, time_diff, dport, is_ephemeral_sport, unique_dports_15s, direction
```

---

## Quickstart (native)

**Requirements:** Python 3.10+, `pip`, Linux recommended for live capture.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Train a model (replace <iface> and <packet_count>)
python3 main.py train -i <iface> -c <packet_count> -m models/iforest.joblib

# Verify the saved bundle
python3 main.py verify-model -m models/iforest.joblib

# Monitor live traffic using the bundle
python3 main.py monitor -i <iface> -m models/iforest.joblib
```

## Configuration (`config.ini`)

Common knobs (defaults are safe):

| Section        | Key                       | Example                  | Notes                                      |
| -------------- | ------------------------- | ------------------------ | ------------------------------------------ |
| `Monitoring` | `AlertThresholds`       | `-0.10, -0.05`         | score → `high                             |
| `Monitoring` | `OnlineRetrainInterval` | `0` or `100`         | retrain every*K* packets (0 = disabled)  |
| `Monitoring` | `FirewallBlocking`      | `false`                | auto-block high severity anomalies         |
| `Monitoring` | `SimulateTraffic`       | `false`                | generate synthetic packets when monitoring |
| `Training`   | `SaveRollingParquet`    | `true`                 | enable Parquet persistence                 |
| `Training`   | `RollingParquetPath`    | `data/rolling.parquet` | path for engineered rows                   |
| `Logging`    | `LogLevel`              | `INFO`                 | `DEBUG                                     |
| `Signatures` | `Enable`                | `true`                 | master toggle                              |
| `Signatures` | `PortScanThreshold`     | `10`                   | trigger level for port scan rule           |
| `Signatures` | `SensitivePorts`        | `22,23,2323,3389,5900` | inbound sensitive port set                 |
| `Signatures` | `DedupSeconds`          | `5.0`                  | rate-limit repeated signature hits         |

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
python3 main.py train -i <iface> -c <packet_count> -m models/iforest.joblib
```

Outputs:

- `Capturing ... for training…`
- `Training Isolation Forest…`
- `Model trained and saved to: models/iforest.joblib`

### Verify

```bash
python3 main.py verify-model -m models/iforest.joblib
```

Prints: Version, Trained at, IF params, Feature count, Feature checksum, Feature order.

### Monitor

```bash
# Live capture on an interface
python3 main.py monitor -i <iface> -m models/iforest.joblib

# Add --firewall-blocking to drop high-severity sources via iptables (requires root)
python3 main.py monitor -i <iface> -m models/iforest.joblib --firewall-blocking

# Generate synthetic traffic without touching your NIC
python3 main.py monitor -i lo -m models/iforest.joblib --simulate-traffic
```

Startup banner includes model metadata + thresholds. Alerts:

```
ANOMALY: ts=... <src_ip> -> <dest_ip> proto=<n> size=<bytes> dport=<n> eph_sport=<0/1> unique_dports_15s=<n> direction=<in|out> score=<float> severity=<low|medium|high>
SIGNATURE: <name> severity=<sev> | <src> -> <dest> dport=<n> desc="..."
```

---

## SignatureEngine (Sprint-1)

- Rules are simple Python callables evaluated on the latest engineered row + current window.
- Default rules:
  - `port-scan-suspected` *(high)* — `unique_dports_15s ≥ PortScanThreshold`
  - `inbound-sensitive-port` *(medium)* — `direction == 0` and `dport ∈ SensitivePorts`
- Severity → log level: `high→ERROR`, `medium→WARNING`, `low→INFO`.
- Optional dedup: once per `(rule, src, dest)` in `DedupSeconds`.

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

## Continuous integration

All pull requests and pushes run through our [GitHub Actions pipeline](docs/ci_pipeline.md). The workflow mirrors the helper scripts in `scripts/`, so you can reproduce the same lint, type-check, and test steps locally with `bash scripts/test_fast.sh` (PR checks) or `bash scripts/test_full.sh` (push/nightly checks).

## Deployment (CD pipeline)

The deployment workflow (`cd_pipeline.yml`) builds a container image and can roll the stack out to a remote host via SSH. To wire it up:

1. **Prep the host**

   - Copy this repository to the server and run `sudo ./setup-server.sh` from the repo root. The script installs Docker, the Compose plugin, Nginx, and prepares `/opt/ai-ids` with the bind-mount directories used by `docker-compose.yml`.
   - Provide TLS certs in `/opt/ai-ids/ssl` if you intend to enable HTTPS in `nginx.conf`.
2. **Configure repository secrets**

   - `DEPLOY_HOST`, `DEPLOY_USER`, `SSH_PRIVATE_KEY` — SSH details for the deployment target.
   - `GHCR_PAT` — a Personal Access Token with `read:packages` on the container registry.
   - `DEPLOY_REPO_TOKEN` — a PAT with `repo` (or `contents:read` for public repos) so the workflow can pull the latest compose bundle on the host.

When the workflow runs it:

- Builds/pushes `ghcr.io/<owner>/<repo>` (lower-cased automatically).
- Logs into GHCR on the remote host before pulling the `latest` tag.
- Syncs the repository on `/opt/ai-ids`, writes `GITHUB_REPOSITORY=<owner>/<repo>` to `.env` for Compose, and ensures bind-mount directories exist.
- Restarts the stack with `docker compose up -d` and performs a simple health check against `/api/healthz`.

## Troubleshooting

- **No packets captured / permission denied:** run as root.
- **Firewall block errors:** the API needs root privileges on Linux with `iptables`; otherwise requests succeed but return `firewall.applied=false`.
- **Parquet file missing:** ensure `SaveRollingParquet=true`, `RollingParquetPath` folder exists, and `pyarrow` is installed; let monitor run for 10–30s.
- **No SIGNATURE lines:** traffic may not match defaults; try a short port scan (`nmap -Pn -p 20-40 <target>` on a permitted host) or inbound to port 22 from another device.
