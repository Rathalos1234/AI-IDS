import pandas as pd
import pytest
import os
from packet_processor import PacketProcessor
from anomaly_detector import AnomalyDetector

pytestmark = pytest.mark.integration


def test_capture_engineer_train_save(tmp_path):
    # "Capture" synthetic packets by building a DataFrame
    pp = PacketProcessor(window_size=1000)
    pp._local_ips = set()
    rows = []
    for i in range(200):
        rows.append(
            {
                "timestamp": 1000.0 + i * 0.01,
                "src_ip": "10.0.0.2" if i % 2 == 0 else "8.8.8.8",
                "dest_ip": "8.8.8.8" if i % 2 == 0 else "10.0.0.2",
                "protocol": 6 if i % 3 else 17,
                "packet_size": 100 + (i % 200),
                "sport": 49152 + (i % 100),
                "dport": 80 if i % 5 else 443,
            }
        )
    df = pd.DataFrame(rows)
    feats, _ = pp.engineer_features(df)

    det = AnomalyDetector(contamination=0.05, n_estimators=100, random_state=42)
    det.train(feats)

    model_path = tmp_path / "models"
    os.makedirs(model_path, exist_ok=True)
    bundle = model_path / "iforest.joblib"
    det.save_model(str(bundle))
    assert bundle.exists()
