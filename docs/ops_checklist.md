# Ops Checklist (Demo-Ready)
## Prep
- Linux host recommended (packet capture).
- Ensure Python 3.10 or use Docker (below).
- Create folders: `mkdir -p models logs data`.

## Train
- Identify iface: `ip -br a` (e.g., `eth0`, `wlan0`).
- Run: `python3 main.py train -i <iface> -c <packet_count> -m models/iforest.joblib`.

## Verify
- Run: `python3 main.py verify-model -m models/iforest.joblib`.
- Confirm: version, trained_at, IF params, feature order/checksum.

## Monitor
- Ensure config thresholds sensible in `config.ini`.
- Run: `python3 main.py monitor -i <iface> -m models/iforest.joblib`.
- Expect: startup banner, `ANOMALY:` lines; if signatures enabled, `SIGNATURE:` lines.

## Artifacts
- Logs: `logs/anomalies.log`
- Parquet (if enabled): `data/rolling.parquet`
- Model: `models/iforest.joblib`
