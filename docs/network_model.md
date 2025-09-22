
# Network Model (Sprint 1)
_Last updated: 2025-09-19 23:48_

This model shows **how traffic flows** from the NIC into the IDS and where operators interact.

## 1) Data flow (text diagram)

```
[Network Interface]
   │  live capture (scapy)
   ▼
Raw Packet  ──▶  PacketProcessor  ──▶  Features DataFrame  ──▶  StandardScaler + IsolationForest  ──▶  Decision/Severity
                              │                                           │
                              └──▶ Rolling Parquet (forensics/retrain)    └──▶ Logs (console + file), Alerts
```

**Feature set (v1):** protocol, packet_size_log, time_diff, dport, is_ephemeral_sport, unique_dports_15s, direction

**Anomaly score → Severity:** model decision scores (more negative = more anomalous) are mapped via `Monitoring.AlertThresholds` to **high / medium / low**.

## 2) Control flow & operator touchpoints
- **Start/Stop:** CLI (`train`, `verify-model`, `monitor`); Docker optional for reproducibility.
- **Triage:** watch console/Alerts, tail `logs/anomalies.log`, and (if available) update **Ban List** for block/unblock.
- **Tuning:** edit `config.ini` (thresholds, contamination, logging, parquet path).

## 3) Deployment surfaces
- **Bare metal / VM:** Python 3.10+, `requirements.txt`.
- **Container:** Docker image to unify runtime (`docker build -t ai-ids:dev .`, then `docker run …`).

## 4) Data stores
- **Logs:** `logs/` (file logging enabled by config).
- **Model bundle:** `models/iforest.joblib`.
- **Forensics:** `data/rolling.parquet`.

## 5) Assumptions & scope (Sprint‑1)
- Single-host monitoring for demo; packet capture requires elevated privileges.
- Signature engine is planned; Sprint‑1 focuses on anomaly path and ops evidence.