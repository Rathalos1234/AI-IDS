# tests/test_faults_and_edges.py
import pytest
import pandas as pd
from packet_processor import PacketProcessor
from anomaly_detector import AnomalyDetector
import joblib

pytestmark = pytest.mark.unit


@pytest.mark.unit
def test_missing_columns_raises_clear_error():
    pp = PacketProcessor()
    df = pd.DataFrame(
        [
            {
                "timestamp": 1.0,
                "src_ip": "a",
                "dest_ip": "b",
                "packet_size": 100,
                "dport": 80,
            }
        ]
    )  # no protocol/sport
    with pytest.raises(Exception):
        pp.engineer_features(df)


@pytest.mark.unit
def test_load_broken_bundle_raises(tmp_path):
    bad = {"feature_names": ["x", "y"]}  # missing 'meta'
    p = tmp_path / "bad.joblib"
    joblib.dump(bad, p)
    det = AnomalyDetector()
    with pytest.raises(Exception):
        det.load_model(str(p))
