# PT-11: WebDB tests (importorskip)
import pytest

webdb = pytest.importorskip("webdb", reason="webdb module not found")

pytestmark = pytest.mark.unit


@pytest.fixture()
def fresh_db(tmp_path, monkeypatch):
    db_path = tmp_path / "ids_test.db"
    monkeypatch.setattr(webdb, "DB", db_path)
    webdb.init()
    return webdb


def test_schema_init_and_list(fresh_db):
    alerts = fresh_db.list_alerts(limit=1)
    blocks = fresh_db.list_blocks(limit=1)
    assert isinstance(alerts, list)
    assert isinstance(blocks, list)


def test_record_device_preserves_name_and_ignores_blank(fresh_db):
    fresh_db.record_device("192.0.2.3", "Printer")
    fresh_db.record_device("192.0.2.3", "")
    fresh_db.record_device("", "Ignored")

    devices = fresh_db.list_devices()
    assert len(devices) == 1
    device = devices[0]
    assert device["ip"] == "192.0.2.3"
    assert device["name"] == "Printer"


def test_set_device_scan_updates_inventory(fresh_db):
    fresh_db.set_device_scan("198.51.100.8", "22,80", risk="high")

    devices = {row["ip"]: row for row in fresh_db.list_devices()}
    assert "198.51.100.8" in devices
    assert devices["198.51.100.8"]["open_ports"] == "22,80"
    assert devices["198.51.100.8"]["risk"] == "high"


def test_expire_bans_generates_unblock_event(fresh_db):
    fresh_db.insert_block(
        {
            "id": "block1",
            "ts": "2024-01-01T00:00:00Z",
            "ip": "203.0.113.77",
            "action": "block",
            "reason": "temp",
            "expires_at": "2024-01-02T00:00:00Z",
        }
    )

    fresh_db.expire_bans("2024-01-03T00:00:00Z")

    blocks = [b for b in fresh_db.list_blocks(limit=5) if b["ip"] == "203.0.113.77"]
    actions = {b["action"] for b in blocks}
    assert "unblock" in actions
    assert any(
        b["reason"] == "auto-expired" for b in blocks if b["action"] == "unblock"
    )
