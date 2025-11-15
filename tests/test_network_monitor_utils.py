import configparser
import importlib
import math
import sys
import types
from unittest.mock import Mock, call

import pytest


@pytest.fixture()
def network_monitor_module(monkeypatch, tmp_path):
    fake_scapy = types.ModuleType("scapy")
    fake_scapy_all = types.ModuleType("scapy.all")
    setattr(fake_scapy_all, "sniff", lambda *args, **kwargs: None)
    setattr(fake_scapy, "all", fake_scapy_all)
    monkeypatch.setitem(sys.modules, "scapy", fake_scapy)
    monkeypatch.setitem(sys.modules, "scapy.all", fake_scapy_all)
    monkeypatch.setenv("SQLITE_DB", str(tmp_path / "ids_test.db"))
    sys.modules.pop("network_monitor", None)
    module = importlib.import_module("network_monitor")
    return module


def _build_config(
    enable_signatures: bool, thresholds: str | None = None
) -> configparser.ConfigParser:
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


def test_emit_routes_logs_by_severity(network_monitor_module):
    mod = network_monitor_module
    monitor = mod.NetworkMonitor(_build_config(enable_signatures=True))

    fake_logger = Mock()
    monitor.logger = fake_logger

    monitor._emit("critical", "high")
    monitor._emit("degraded", "medium")
    monitor._emit("ok", "low")
    monitor._emit("fallback", None)

    assert fake_logger.error.call_args_list == [call("critical")]
    assert fake_logger.warning.call_args_list == [call("degraded")]
    assert fake_logger.info.call_args_list == [call("ok"), call("fallback")]


@pytest.mark.parametrize(
    "score, expected",
    [(-0.20, "high"), (-0.06, "medium"), (0.01, "low"), (None, "unknown")],
)
def test_severity_from_score_boundaries(network_monitor_module, score, expected):
    mod = network_monitor_module
    monitor = mod.NetworkMonitor(_build_config(enable_signatures=True))

    assert monitor._severity_from_score(score) == expected


def test_maybe_firewall_block_persists_and_tracks(monkeypatch, network_monitor_module):
    mod = network_monitor_module
    cfg = _build_config(enable_signatures=True)
    monitor = mod.NetworkMonitor(cfg)

    monitor.logger = Mock()
    monitor.processor._local_ips = set()

    calls = []

    def fake_firewall(ip, reason):
        calls.append((ip, reason))
        return True, None

    monkeypatch.setattr(mod, "firewall_ensure_block", fake_firewall)

    deletes: list[tuple[str, str]] = []
    inserts: list[dict] = []

    def track_delete(ip: str, action: str) -> None:
        deletes.append((ip, action))

    monkeypatch.setattr(mod.webdb, "delete_action_by_ip", track_delete)
    monkeypatch.setattr(
        mod.webdb, "insert_block", lambda payload: inserts.append(payload)
    )
    monkeypatch.setattr(mod.webdb, "is_trusted", lambda candidate: False)

    monitor._maybe_firewall_block("203.0.113.5", "high", "scan burst")

    assert calls == [("203.0.113.5", "auto-high")]
    assert ("203.0.113.5", "unblock") in deletes
    assert ("203.0.113.5", "block") in deletes
    assert inserts and inserts[0]["ip"] == "203.0.113.5"
    assert inserts[0]["reason"] == "auto-high"
    assert "203.0.113.5" in monitor._runtime_blocked
    monitor.logger.warning.assert_called_once()


def _prep_none(_monitor, _mod, _monkeypatch):
    return None


def _prep_already_blocked(ip):
    def _inner(monitor, _mod, _monkeypatch):
        monitor._runtime_blocked.add(ip)

    return _inner


def _prep_local_ip(ip):
    def _inner(monitor, _mod, _monkeypatch):
        monitor.processor._local_ips = {ip}

    return _inner


def _prep_trusted(ip):
    def _inner(_monitor, mod, monkeypatch):
        monkeypatch.setattr(mod.webdb, "is_trusted", lambda candidate: candidate == ip)

    return _inner


@pytest.mark.parametrize(
    "ip, prep",
    [
        ("", _prep_none),
        ("198.51.100.1", _prep_already_blocked("198.51.100.1")),
        ("10.0.0.5", _prep_local_ip("10.0.0.5")),
        ("127.0.0.1", _prep_none),
        ("203.0.113.9", _prep_trusted("203.0.113.9")),
    ],
)
def test_maybe_firewall_block_skips_non_actionable(
    ip, prep, monkeypatch, network_monitor_module
):
    mod = network_monitor_module
    monitor = mod.NetworkMonitor(_build_config(enable_signatures=True))

    monitor.logger = Mock()
    monitor.processor._local_ips = set()
    monitor._runtime_blocked = set()

    monkeypatch.setattr(mod.webdb, "is_trusted", lambda candidate: False)

    calls = []

    def record_call(addr: str, reason: str):
        calls.append((addr, reason))
        return True, None

    monkeypatch.setattr(mod, "firewall_ensure_block", record_call)

    prep(monitor, mod, monkeypatch)

    before = monitor._runtime_blocked.copy()
    monitor._maybe_firewall_block(ip, "high", "ctx")

    assert calls == []
    assert monitor._runtime_blocked == before
