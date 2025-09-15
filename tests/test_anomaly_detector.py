import numpy as np
import pandas as pd
import pytest

from anomaly_detector import AnomalyDetector

pytestmark = pytest.mark.unit


def _make_X(n=200, d=4, seed=123):
    rng = np.random.default_rng(seed)
    X = rng.normal(0, 1, size=(n, d))
    cols = [f"f{i}" for i in range(d)]
    return pd.DataFrame(X, columns=cols)


def test_train_save_load_round_trip(tmp_path):
    X = _make_X(128, 5, seed=1)
    det = AnomalyDetector(contamination=0.05, n_estimators=100, random_state=42)
    det.train(X)
    p = tmp_path / "iforest.joblib"
    det.save_model(str(p))
    assert p.exists()

    det2 = AnomalyDetector(contamination=0.05, n_estimators=100, random_state=42)
    det2.load_model(str(p))
    # feature names preserved
    assert det2.feature_names == det.feature_names

    # predictions identical after load
    y1 = det.predict(X)
    y2 = det2.predict(X)
    assert np.array_equal(np.asarray(y1), np.asarray(y2))


def test_reindex_safety_same_predictions():
    X = _make_X(64, 3, seed=2)
    det = AnomalyDetector(contamination=0.1, n_estimators=50, random_state=0)
    det.train(X)
    y_ref = det.predict(X)

    # shuffle columns
    cols_shuffled = list(reversed(X.columns))
    X_shuffled = X[cols_shuffled]
    y_shuf = det.predict(X_shuffled)
    assert np.array_equal(np.asarray(y_ref), np.asarray(y_shuf))


def test_determinism_with_fixed_seed():
    X = _make_X(200, 4, seed=3)
    det1 = AnomalyDetector(contamination=0.05, n_estimators=50, random_state=123)
    det2 = AnomalyDetector(contamination=0.05, n_estimators=50, random_state=123)
    det1.train(X)
    det2.train(X)
    s1 = det1.decision_scores(X)
    s2 = det2.decision_scores(X)
    # exact equality is acceptable here with fixed seed + same lib versions
    assert np.allclose(np.asarray(s1), np.asarray(s2))
