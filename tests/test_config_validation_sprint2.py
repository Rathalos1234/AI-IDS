# PT-6 / PT-16: Config & Settings validation tests
import configparser
import pytest
from config_validation import validate_config

pytestmark = pytest.mark.unit


def _base_cfg():
    cfg = configparser.ConfigParser()
    cfg.read_dict(
        {
            "DEFAULT": {"DefaultWindowSize": "500", "DefaultPacketCount": "1000"},
            "IsolationForest": {
                "Contamination": "0.05",
                "NEstimators": "50",
                "RandomState": "42",
            },
            "Logging": {"EnableFileLogging": "false", "LogLevel": "INFO"},
            "Monitoring": {
                "AlertThresholds": "-0.20, -0.10",
                "OnlineRetrainInterval": "0",
            },
        }
    )
    return cfg


def test_config_validation_ok():
    cfg = _base_cfg()
    validate_config(cfg)  # should not raise


def test_threshold_order_invalid():
    cfg = _base_cfg()
    cfg.set("Monitoring", "AlertThresholds", "0.10, -0.05")
    with pytest.raises(ValueError) as ei:
        validate_config(cfg)
    assert "AlertThresholds" in str(ei.value)


def test_invalid_log_level():
    cfg = _base_cfg()
    cfg.set("Logging", "LogLevel", "VERBOSE")
    with pytest.raises(ValueError):
        validate_config(cfg)


def test_nonpositive_window_size():
    cfg = _base_cfg()
    cfg.set("DEFAULT", "DefaultWindowSize", "0")
    with pytest.raises(ValueError):
        validate_config(cfg)
