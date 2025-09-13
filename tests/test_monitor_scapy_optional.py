import pytest
import configparser

scapy = pytest.importorskip("scapy")  # skip entire module if scapy is not installed

from network_monitor import NetworkMonitor  # noqa: E402


pytestmark = [pytest.mark.integration, pytest.mark.scapy_required]


def test_severity_mapping_no_crash():
    cfg = configparser.ConfigParser()
    cfg.read_dict(
        {
            "DEFAULT": {
                "DefaultWindowSize": "100",
                "ModelPath": "models/iforest.joblib",
            },
            "IsolationForest": {
                "Contamination": "0.05",
                "NEstimators": "10",
                "RandomState": "42",
            },
            "Logging": {"EnableFileLogging": "false", "LogLevel": "INFO"},
            "Monitoring": {"OnlineRetrainInterval": "0"},
        }
    )
    nm = NetworkMonitor(cfg)
    # Ensure mapping returns a string for representative scores
    for s in [-0.9, -0.3, 0.0, 0.3, 0.9]:
        sev = nm._severity_from_score(s)
        assert isinstance(sev, str)
