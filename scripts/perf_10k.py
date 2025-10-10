import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import time
import pandas as pd
from packet_processor import PacketProcessor
from anomaly_detector import AnomalyDetector


def make_df(n=10_000):
    rows = []
    t0 = time.time()
    for i in range(n):
        rows.append(
            {
                "timestamp": t0 + i * 0.001,
                "src_ip": "10.0.0.2" if i % 2 == 0 else "8.8.8.8",
                "dest_ip": "8.8.8.8" if i % 2 == 0 else "10.0.0.2",
                "protocol": 6 if i % 3 else 17,
                "packet_size": 100 + (i % 512),
                "sport": 49152 + (i % 1000),
                "dport": 80 if i % 5 else 443,
            }
        )
    return pd.DataFrame(rows)


def main():
    pp = PacketProcessor(window_size=15_000)
    pp._local_ips = set()

    t0 = time.time()
    df = make_df()
    feats, _ = pp.engineer_features(df)
    t1 = time.time()

    det = AnomalyDetector(contamination=0.05, n_estimators=100, random_state=42)
    det.train(feats)
    # scores = det.decision_scores(feats)
    t2 = time.time()

    print(
        f"feature_engineering_sec={t1 - t0:.3f} train+score_sec={t2 - t1:.3f} rows={len(df)}"
    )


if __name__ == "__main__":
    main()
