from core.bus import bus
from core import store
from datetime import datetime
import json

def on_detection(det):
    alert = {
        "ts": det.get("ts", datetime.utcnow().isoformat()),
        "src_ip": det["src_ip"],
        "label": det["label"],
        "severity": det["severity"],
        "kind": det["kind"],
        "details": json.dumps(det.get("details", {}))
    }
    store.save_alert(alert)
    if det["severity"] == "high":
        store.block_ip(det["src_ip"])

def main():
    store.init_db()
    print("[response] waiting for detections...]")
    for _, det in bus.consume("detections", group="resp-g", consumer="resp-1"):
        on_detection(det)

if __name__ == "__main__":
    main()
