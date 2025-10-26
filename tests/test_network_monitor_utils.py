import configparser
import importlib
import math
import sys
import types

import pytest


@pytest.fixture()
def network_monitor_module(monkeypatch, tmp_path):
    fake_scapy = types.ModuleType("scapy")
    fake_scapy_all = types.ModuleType("scapy.all")
    fake_scapy_all.sniff = lambda *args, **kwargs: None
    monkeypatch.setitem(sys.modules, "scapy", fake_scapy)
    monkeypatch.setitem(sys.modules, "scapy.all", fake_scapy_all)
    monkeypatch.setenv("SQLITE_DB", str(tmp_path / "ids_test.db"))
    sys.modules.pop("network_monitor", None)
    module = importlib.import_module("network_monitor")
    return module


def _build_config(enable_signatures: bool, thresholds: str | None = None) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    monitoring = {"OnlineRetrainInterval": "1"}
    if thresholds is not None:
        monitoring["AlertThresholds"] = thresholds
    cfg.read_dict(
        {
            "DEFAULT": {
                "DefaultWindowSize": "100",
                "ModelPath": "models/iforest.joblib",
            },
            "IsolationForest": {
                "Contamination": "0.03",
                "NEstimators": "32",
                "RandomState": "7",
            },
            "Logging": {"EnableFileLogging": "false", "LogLevel": "warning"},
            "Monitoring": monitoring,
            "Training": {"SaveRollingParquet": "false", "RollingParquetPath": "noop"},
            "Signatures": {"Enable": "true" if enable_signatures else "false"},
        }
    )
    return cfg


def test_numeric_coercion_helpers_cover_edge_cases(network_monitor_module):
    mod = network_monitor_module
    assert mod._as_int(True) == 1
    assert mod._as_int(12.7) == 12
    assert mod._as_int("15.2") == 15
    assert mod._as_int("not-a-number", default=99) == 99
    assert mod._as_int(math.nan, default=-3) == -3

    assert mod._as_float(1) == 1.0
    assert mod._as_float("3.14") == pytest.approx(3.14)
    assert math.isnan(mod._as_float("nan"))


def test_threshold_parsing_and_signature_toggle(network_monitor_module):
    mod = network_monitor_module
    cfg = _build_config(enable_signatures=False, thresholds=" -0.25 , -0.1 ")

    monitor = mod.NetworkMonitor(cfg)

    assert monitor._thr_high == pytest.approx(-0.25)
    assert monitor._thr_med == pytest.approx(-0.1)
    assert monitor.enable_sigs is False
    assert monitor.sig_engine is None
    assert monitor.save_rolling is False


def test_threshold_fallback_to_defaults(network_monitor_module):
    mod = network_monitor_module
    cfg = _build_config(enable_signatures=True, thresholds="invalid-value")

    monitor = mod.NetworkMonitor(cfg)

    assert monitor._thr_high == pytest.approx(-0.10)
    assert monitor._thr_med == pytest.approx(-0.05)
    assert monitor.enable_sigs is True
    assert monitor.sig_engine is not None