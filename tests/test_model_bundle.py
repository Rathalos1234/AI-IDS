import joblib
import os
import pytest

pytestmark = pytest.mark.unit

MODEL = os.environ.get("IDS_MODEL", "models/iforest.joblib")
EXPECTED = [
    "protocol",
    "packet_size_log",
    "time_diff",
    "dport",
    "is_ephemeral_sport",
    "unique_dports_15s",
    "direction",
]


def test_feature_order_checksum_and_version():
    payload = joblib.load(MODEL)
    names = payload["feature_names"]
    meta = payload["meta"]
    assert names == EXPECTED
    assert (
        isinstance(meta.get("feature_checksum", ""), str)
        and len(meta["feature_checksum"]) == 64
    )
    assert meta.get("version") == "1.0.0"
