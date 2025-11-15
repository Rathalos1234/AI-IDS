"""Targeted tests for NetworkMonitor anomaly and signature handling."""

from __future__ import annotations

import configparser
import importlib
import sys
import threading
import types
from collections import deque
from unittest.mock import Mock

import pandas as pd
import pytest

from signature_engine import SigResult


@pytest.fixture
def monitor_module(monkeypatch, tmp_path):
    fake_scapy = types.ModuleType("scapy")
    fake_scapy_all = types.ModuleType("scapy.all")
    setattr(fake_scapy_all, "sniff", lambda *args, **kwargs: None)
    setattr(fake_scapy, "all", fake_scapy_all)
    monkeypatch.setitem(sys.modules, "scapy", fake_scapy)
    monkeypatch.setitem(sys.modules, "scapy.all", fake_scapy_all)
    monkeypatch.setenv("SQLITE_DB", str(tmp_path / "ids_runtime.db"))
    sys.modules.pop("network_monitor", None)
    return importlib.import_module("network_monitor")


def _config(enable_signatures: bool = True) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read_dict(
        {
            "DEFAULT": {
                "DefaultWindowSize": "64",
                "ModelPath": "models/iforest.joblib",
            },
            "IsolationForest": {
                "Contamination": "0.05",
                "NEstimators": "8",
                "RandomState": "1",
            },
            "Logging": {"EnableFileLogging": "false", "LogLevel": "warning"},
            "Monitoring": {
                "OnlineRetrainInterval": "0",
                "AlertThresholds": "-0.2, -0.1",
            },
            "Training": {"SaveRollingParquet": "false", "RollingParquetPath": "noop"},
            "Signatures": {"Enable": "true" if enable_signatures else "false"},
        }
    )
    return cfg


class _StubProcessor:
    def __init__(
        self,
        window_df: pd.DataFrame,
        processed_df: pd.DataFrame,
        features_df: pd.DataFrame,
    ) -> None:
        self._window_df = window_df
        self._processed_df = processed_df
        self._features_df = features_df
        self.packet_data = []
        self._local_ips = set()

    def process_packet(self, packet) -> None:  # noqa: D401 - simple stub
        self._last_packet = packet

    def get_dataframe(self) -> pd.DataFrame:
        return self._window_df

    def engineer_features(self, df: pd.DataFrame):
        assert df is self._window_df
        return self._features_df, self._processed_df


class _StubDetector:
    def __init__(self, *, label: str, score: float) -> None:
        self._label = label
        self._score = score

    def predict(self, df: pd.DataFrame):  # noqa: D401 - simple stub
        return [self._label]

    def decision_scores(self, df: pd.DataFrame):
        return [self._score]


def _make_frames(seed: int, count: int = 60):
    base_ts = 1680001000.0 + seed * 10.0
    rows = [
        {
            "timestamp": base_ts + i * 0.25,
            "src_ip": f"203.0.113.{50 + seed}",
            "dest_ip": "10.0.0.5",
            "protocol": 6,
            "packet_size": 512,
            "dport": 4000 + seed,
            "sport": 52000 + i,
            "unique_dports_15s": 5 + (i % 3),
            "direction": 1,
        }
        for i in range(count)
    ]
    window_df = pd.DataFrame(rows)
    processed_df = window_df.copy()
    features_df = pd.DataFrame({"f1": [float(seed)] * count})
    return window_df, processed_df, features_df


def test_anomaly_path_invokes_firewall_and_alert(monkeypatch, monitor_module):
    mod = monitor_module
    monitor = mod.NetworkMonitor(_config(enable_signatures=False))
    monitor.logger = Mock()
    monitor.firewall_runtime_enabled = True
    monitor.sig_engine = None

    row = {
        "timestamp": 1680000000.0,
        "src_ip": "203.0.113.50",
        "dest_ip": "10.0.0.5",
        "protocol": 6,
        "packet_size": 512,
        "dport": 3389,
        "sport": 62000,
        "unique_dports_15s": 12,
        "direction": 1,
    }
    window_df = pd.DataFrame([row])
    processed_df = window_df.copy()
    features_df = pd.DataFrame([[1.0]], columns=["f1"])

    monitor.processor = _StubProcessor(window_df, processed_df, features_df)
    monitor.detector = _StubDetector(label="Anomaly", score=-0.35)
    monitor._maybe_firewall_block = Mock()
    monitor._emit = Mock()

    alerts: list[dict] = []
    monkeypatch.setattr(
        mod.webdb, "insert_alert", lambda payload: alerts.append(payload)
    )
    monkeypatch.setattr(mod.webdb, "record_device", lambda ip: None)
    monkeypatch.setattr(mod.webdb, "delete_action_by_ip", lambda ip, action: None)
    monkeypatch.setattr(mod.webdb, "is_trusted", lambda candidate: False)

    monitor._analyze_packet(object())

    monitor._maybe_firewall_block.assert_called_once()
    args = monitor._maybe_firewall_block.call_args[0]
    assert args[0] == row["src_ip"]
    assert args[1] == "high"
    assert alerts and alerts[0]["kind"] == "ANOMALY"


def test_signature_hits_emit_alert(monkeypatch, monitor_module):
    mod = monitor_module
    monitor = mod.NetworkMonitor(_config(enable_signatures=True))
    monitor.logger = Mock()

    row = {
        "timestamp": 1680000100.0,
        "src_ip": "198.51.100.9",
        "dest_ip": "10.0.0.7",
        "protocol": 6,
        "packet_size": 400,
        "dport": 22,
        "sport": 54000,
        "unique_dports_15s": 1,
        "direction": 0,
    }
    window_df = pd.DataFrame([row])
    processed_df = window_df.copy()
    features_df = pd.DataFrame([[0.0]], columns=["f1"])

    monitor.processor = _StubProcessor(window_df, processed_df, features_df)
    monitor.detector = _StubDetector(label="Normal", score=-0.02)
    monitor.firewall_runtime_enabled = True
    monitor._maybe_firewall_block = Mock()

    emissions: list[tuple[str, str]] = []
    monitor._emit = lambda msg, severity: emissions.append((msg, severity))

    hits = [SigResult(name="custom", severity="medium", description="test-hit")]
    monitor.sig_engine = type(
        "_Sig", (), {"evaluate": lambda self, last_row, df: hits}
    )()

    alerts: list[dict] = []
    monkeypatch.setattr(
        mod.webdb, "insert_alert", lambda payload: alerts.append(payload)
    )
    monkeypatch.setattr(mod.webdb, "record_device", lambda ip: None)

    monitor._analyze_packet(object())

    assert emissions and emissions[0][1] == "medium"
    assert alerts and alerts[0]["kind"] == "SIGNATURE"
    monitor._maybe_firewall_block.assert_not_called()


def test_firewall_sync_on_monitor_startup(monkeypatch, monitor_module):
    mod = monitor_module
    monitor = mod.NetworkMonitor(_config(enable_signatures=False))
    monitor.logger = Mock()
    monitor.firewall_capabilities = {"supported": True}

    applied: list[tuple[str, str]] = []

    def _fake_block(ip: str, reason: str):
        applied.append((ip, reason))
        return True, None

    monkeypatch.setattr(mod, "firewall_ensure_block", _fake_block)
    monkeypatch.setattr(
        mod.webdb,
        "list_blocks",
        lambda limit=5000: [
            {"ip": "198.51.100.5", "action": "block", "reason": "manual"},
            {"ip": "203.0.113.1", "action": "allow", "reason": ""},
            {"ip": "198.51.100.5", "action": "block", "reason": "duplicate"},
        ],
    )

    detector = Mock()
    detector.load_model = Mock()
    detector.bundle_metadata.return_value = {
        "version": "1.0.0",
        "trained_at": "",
        "feature_names": ["f1"],
        "feature_count": 1,
        "feature_checksum": "abc",
        "params": {},
    }
    monitor.detector = detector

    monitor.start_monitoring(
        interface="eth0",
        model_path="noop.joblib",
        firewall_blocking=True,
        simulate=True,
    )

    assert ("198.51.100.5", "manual") in applied
    assert applied.count(("198.51.100.5", "manual")) == 1
    detector.load_model.assert_called_once_with("noop.joblib")


def test_online_retrain_runs_alongside_packet_processing(monkeypatch, monitor_module):
    """
    Retraining in one thread should not block packet analysis in the main thread.

    Test flow:
    1. First packet triggers analysis + first retrain (blocks on event)
    2. Second packet analyzed while first retrain is paused
    3. First retrain completes, second retrain starts
    4. Verify both packets processed and both retrains completed
    """

    mod = monitor_module
    monitor = mod.NetworkMonitor(_config(enable_signatures=False))
    monitor.logger = Mock()
    monitor.firewall_runtime_enabled = False
    monitor._maybe_firewall_block = Mock()
    monitor.sig_engine = None
    monitor.online_retrain_interval = 1

    frames = deque([_make_frames(0), _make_frames(1)])

    class _ConcurrentProcessor:
        def __init__(self, frame_queue: deque):
            self._frames = frame_queue
            self._lock = threading.Lock()
            self.packet_data = []
            self._current = None

        def process_packet(self, packet) -> None:
            with self._lock:
                if not self._frames:
                    raise AssertionError("no frames left for processing")
                self.packet_data.append(packet)
                self._current = self._frames[0]

        def get_dataframe(self) -> pd.DataFrame:
            with self._lock:
                if self._current is None:
                    return pd.DataFrame()
                return self._current[0]

        def engineer_features(self, df: pd.DataFrame):
            with self._lock:
                window_df, processed_df, features_df = self._frames.popleft()
                self._current = None
            return features_df, processed_df

    monitor.processor = _ConcurrentProcessor(frames)

    saved_paths: list[str] = []
    first_train_started = threading.Event()
    first_train_can_finish = threading.Event()
    all_trains_done = threading.Event()

    class _ConcurrentDetector:
        def __init__(self) -> None:
            self.predict_calls = 0
            self.train_calls = 0
            self._lock = threading.Lock()

        def predict(self, df: pd.DataFrame):
            with self._lock:
                self.predict_calls += 1
            return ["Anomaly"]

        def decision_scores(self, df: pd.DataFrame):
            return [-0.55]

        def train(self, df: pd.DataFrame) -> None:
            with self._lock:
                idx = self.train_calls
                self.train_calls += 1

            if idx == 0:
                first_train_started.set()
                first_train_can_finish.wait(timeout=5)

            with self._lock:
                if self.train_calls >= 2:
                    all_trains_done.set()

        def save_model(self, path: str) -> None:
            saved_paths.append(path)

    monitor.detector = _ConcurrentDetector()

    alerts: list[dict] = []
    alerts_lock = threading.Lock()

    def record_alert(payload):
        with alerts_lock:
            alerts.append(payload)
        return payload

    monkeypatch.setattr(mod.webdb, "insert_alert", record_alert)
    monkeypatch.setattr(mod.webdb, "record_device", lambda ip: None)
    monkeypatch.setattr(mod.webdb, "is_trusted", lambda ip: False)

    monitor._analyze_packet(object())
    assert first_train_started.wait(timeout=2), "First retrain should have started"
    monitor._analyze_packet(object())
    assert monitor.detector.predict_calls == 2, "Both packets should be analyzed"
    assert monitor._packet_counter == 2, "Packet counter should be 2"
    assert monitor.detector.train_calls == 1, "First retrain should be running"
    first_train_can_finish.set()
    assert all_trains_done.wait(timeout=5), "Both retrains should complete"
    assert monitor.detector.train_calls == 2, "Both retrains should have completed"
    assert len(saved_paths) == 2, "Model should be saved twice"
    assert len(alerts) == 2, "Both anomalies should be recorded"

    for payload in alerts:
        assert payload["kind"] == "ANOMALY"
