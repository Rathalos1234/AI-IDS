# AI‑Powered IDS (Isolation Forest)

A lightweight packet anomaly detector using Scapy + Isolation Forest.

## Install
```bash
python3 -m venv .venv && source .venv/bin/activate   # (Windows: .venv\Scripts\activate)
pip install -r requirements.txt
```

## Configure
Edit `config.ini`:
- `DEFAULT.DefaultInterface`: e.g., `eth0`, `wlan0`
- `DEFAULT.ModelPath`: where the trained model is stored
- `IsolationForest.*`: contamination, trees, seed
- `Logging.*`: enable file logs and level
- `Monitoring.OnlineRetrainInterval`: 0 to disable

## Train
Capture N packets and fit the model:
```bash
python3 main.py train --interface <iface> --count 1000 --model models/iforest.joblib
```

## Monitor
Run live detection with the trained model:
```bash
python3 main.py monitor --interface <iface> --model models/iforest.joblib
```

## Notes
- Sniffing may require elevated privileges (`sudo` on Linux).
- Logs go to console and (optionally) the `logs/` directory.
- For production, pin package versions in `requirements.txt`.