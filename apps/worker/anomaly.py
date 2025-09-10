import os, joblib, numpy as np
from datetime import datetime
from sklearn.ensemble import IsolationForest
from core.bus import bus

MODEL_PATH = "ml/model.joblib"
FEATURES = ["pkts","bytes","uniq_dsts","uniq_dst_ports","syn_rate","rst_rate","failed_auth_rate","avg_len"]

def load_or_init():
    if os.path.exists(MODEL_PATH):
        return joblib.load(MODEL_PATH)
    model = IsolationForest(contamination=0.02, random_state=42)
    X = np.random.normal(loc=[200, 100000, 5, 10, 5, 2, 1, 600], scale=[50, 20000, 2, 4, 2, 1, 1, 100], size=(500,8))
    model.fit(X)
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    return model

model = load_or_init()

def to_vec(feat):
    return np.array([[feat.get(k,0) for k in FEATURES]])

def main():
    print("[anomaly] waiting for features...]")
    for _, feat in bus.consume("features", group="ml-g", consumer="ml-1"):
        X = to_vec(feat)
        score = -float(model.score_samples(X)[0])
        if score > 0.6:
            det = {
                "ts": datetime.utcnow().isoformat(),
                "src_ip": feat["src_ip"],
                "kind": "anomaly",
                "label": "anomaly",
                "score": round(score, 3),
                "severity": "medium" if score < 1.2 else "high",
                "details": {}
            }
            bus.publish("detections", det)

if __name__ == "__main__":
    main()
