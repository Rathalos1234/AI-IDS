# PT-19: Scan API
import pytest

api = pytest.importorskip("api", reason="API app not found")

pytestmark = pytest.mark.unit


def test_scan_start_and_status_contract():
    c = api.app.test_client()
    # Other tests toggle auth-on; disable to exercise happy path without login.
    api.REQUIRE_AUTH = False
    r = c.post("/api/scan")
    assert r.status_code in (200, 202, 204)
    s = c.get("/api/scan/status")
    assert s.status_code == 200
    payload = s.get_json() or {}
    data = payload.get("scan", payload)
    assert "status" in data, f"Missing 'status' in {data}"
    # progress is typically 0..100
    prog = data.get("progress", 0)
    assert isinstance(prog, (int, float)) and 0 <= prog <= 100
    # last scan timestamp can be named differently; make it soft
    assert any(k in data for k in ("last_scan_ts", "last_ts", "lastScanTs", "ts")), (
        "No last-scan timestamp key found"
    )
    assert 0 <= data["progress"] <= 100
