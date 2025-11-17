# tests/test_train_until_ctrl_c.py
import importlib
import sys
import time
import types
import configparser
from pathlib import Path

import pytest

_ORIGINAL_MODULES = {
    name: sys.modules.get(name) for name in ("scapy", "scapy.all", "config_validation")
}

# --- Bootstrap: stub out external deps BEFORE importing project modules ---
# Fake webdb to avoid DB dependency in CI
fake_webdb = types.ModuleType("webdb")
setattr(fake_webdb, "init", lambda: None)
setattr(fake_webdb, "record_device", lambda *a, **k: None)
setattr(fake_webdb, "insert_alert", lambda *a, **k: None)
setattr(fake_webdb, "delete_action_by_ip", lambda *a, **k: None)
setattr(fake_webdb, "insert_block", lambda *a, **k: None)
setattr(fake_webdb, "is_trusted", lambda ip: False)
setattr(fake_webdb, "list_blocks", lambda *a, **k: [])
setattr(fake_webdb, "list_devices", lambda *a, **k: [])
setattr(fake_webdb, "expire_bans", lambda *a, **k: None)

# Fake scapy so importing network_monitor doesn't fail in environments without scapy
fake_scapy_all = types.ModuleType("scapy.all")
setattr(fake_scapy_all, "sniff", lambda **kwargs: None)
fake_scapy = types.ModuleType("scapy")
setattr(fake_scapy, "all", fake_scapy_all)
sys.modules["scapy"] = fake_scapy
sys.modules["scapy.all"] = fake_scapy_all

# Fake config_validation used by main.py (if your repo already has it, this is harmless)
fake_config_validation = types.ModuleType("config_validation")
setattr(fake_config_validation, "validate_config", lambda cfg: None)
sys.modules["config_validation"] = fake_config_validation

# Now we can import the project
import network_monitor as nm  # noqa: E402
# from packet_processor import IP, TCP, UDP  # noqa: E402

setattr(fake_webdb, "DB", Path("ids_web.db"))
setattr(nm, "webdb", fake_webdb)


@pytest.fixture(scope="module", autouse=True)
def _restore_imports():
    """Restore real modules after this test module finishes."""
    yield
    for name, original in _ORIGINAL_MODULES.items():
        if original is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = original

    # Ensure downstream tests see real implementations again
    importlib.invalidate_caches()

    if "network_monitor" in sys.modules:
        importlib.reload(sys.modules["network_monitor"])
    if "main" in sys.modules:
        importlib.reload(sys.modules["main"])


@pytest.mark.unit
def test_capture_and_train_until_interrupt_saves_model(tmp_path, monkeypatch):
    """
    Arrange: stub sniff to feed synthetic packets then raise KeyboardInterrupt.
    Act:     call capture_and_train_until_interrupt(...)
    Assert:  a model bundle file is created.
    """
    # Build a minimal config
    cfg = configparser.ConfigParser()
    cfg["Training"] = {
        "UntilCtrlCWindow": "2000",  # ensure a reasonably sized window
    }
    cfg["Logging"] = {
        "EnableFileLogging": "false",  # keep test output clean
        "LogLevel": "INFO",
    }
    monitor = nm.NetworkMonitor(cfg)

    # Skip interface validation by pretending netifaces is not available
    monkeypatch.setattr(nm, "netifaces", None, raising=False)

    # Stub sniff: feed N synthetic packets, then simulate Ctrl+C
    def fake_sniff(*, iface, prn, store=0, **_):
        now = time.time()
        # Send a small batch of TCP packets on different dports
        for i in range(30):
            pkt = nm._SyntheticPacket(
                timestamp=now + i * 0.001,
                length=100 + i,
                src="192.168.1.100",
                dest="192.168.1.1",
                proto=6,  # TCP
                sport=50000 + i,
                dport=80 if i < 25 else 443,
            )
            prn(pkt)
        # End capture
        raise KeyboardInterrupt

    monkeypatch.setattr(nm, "sniff", fake_sniff, raising=True)

    model_path = tmp_path / "iforest.joblib"

    # Act
    monitor.capture_and_train_until_interrupt(
        interface="eth0",
        model_path=str(model_path),
        min_packets=10,
    )

    # Assert
    assert model_path.exists(), "Expected model file to be saved after Ctrl+C training"


@pytest.mark.unit
def test_cli_train_until_flag_routes_to_indefinite(monkeypatch, tmp_path):
    """
    Ensure `python main.py train --until-ctrl-c` calls the right method.
    We stub the method to avoid sniff/model training and just leave a breadcrumb.
    """
    # Import main after our stubs (above)
    import main as cli

    monkeypatch.setattr(cli, "webdb", fake_webdb, raising=False)

    called = {"until": False}

    def fake_until(self, interface: str, model_path: str, min_packets: int = 100):
        called["until"] = True
        # simulate successful save
        Path(model_path).write_bytes(b"dummy-model")

    # Make sure the bounded variant isn't used by mistake
    def fake_bounded(*args, **kwargs):
        raise AssertionError(
            "capture_and_train() should not be called when --until-ctrl-c is set"
        )

    monkeypatch.setattr(
        nm.NetworkMonitor, "capture_and_train_until_interrupt", fake_until, raising=True
    )
    monkeypatch.setattr(
        nm.NetworkMonitor, "capture_and_train", fake_bounded, raising=True
    )

    model_path = tmp_path / "cli-iforest.joblib"
    rc = cli.main(
        [
            "train",
            "--interface",
            "eth0",
            "--model",
            str(model_path),
            "--until-ctrl-c",
            "--min-packets",
            "5",
        ]
    )

    assert rc == 0, "CLI should exit 0 on successful training"
    assert called["until"] is True, "Expected indefinite training path to be used"
    assert model_path.exists(), "Expected CLI path to write the model file"
