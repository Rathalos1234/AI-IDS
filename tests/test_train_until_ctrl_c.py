# tests/test_train_until_ctrl_c.py
import sys
import types
import time
import configparser
from pathlib import Path

import pytest

# --- Bootstrap: stub out external deps BEFORE importing project modules ---
# Fake webdb to avoid DB dependency in CI
fake_webdb = types.SimpleNamespace(
    init=lambda: None,
    record_device=lambda *a, **k: None,
    insert_alert=lambda *a, **k: None,
    delete_action_by_ip=lambda *a, **k: None,
    insert_block=lambda *a, **k: None,
    is_trusted=lambda ip: False,
)
sys.modules.setdefault("webdb", fake_webdb)

# Fake scapy so importing network_monitor doesn't fail in environments without scapy
fake_scapy_all = types.SimpleNamespace(sniff=lambda **kwargs: None)
sys.modules.setdefault("scapy", types.SimpleNamespace(all=fake_scapy_all))
sys.modules.setdefault("scapy.all", fake_scapy_all)

# Fake config_validation used by main.py (if your repo already has it, this is harmless)
sys.modules.setdefault(
    "config_validation",
    types.SimpleNamespace(validate_config=lambda cfg: None),
)

# Now we can import the project
import network_monitor as nm  # noqa: E402
# from packet_processor import IP, TCP, UDP  # noqa: E402


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
