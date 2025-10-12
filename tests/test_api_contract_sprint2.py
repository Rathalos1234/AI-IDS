# PT-10/PT-15 core API shapes (+ PD-11 stable endpoints)
import pytest

api = pytest.importorskip("api", reason="API app not found")

pytestmark = pytest.mark.unit


def _c():
    return api.app.test_client()


def _json(res):
    try:
        return res.get_json()
    except Exception:
        return None


def test_stats_devices_events_heads():
    c = _c()
    stats = c.get("/api/stats")
    assert stats.status_code == 200
    data = _json(stats)
    assert isinstance(data, dict)
    # Accept either the flat v1 shape or nested {counts, ts}
    flat_ok = all(
        k in data for k in ("packets", "anomalies", "signatures", "timestamp")
    )
    nested_ok = ("counts" in data) and ("ts" in data)
    assert flat_ok or nested_ok, f"Unexpected /api/stats shape: {list(data.keys())}"

    devs = c.get("/api/devices")
    assert devs.status_code == 200
    arr = _json(devs)
    assert isinstance(arr, list)

    events = c.get("/api/events", headers={"Accept": "text/event-stream"})
    assert events.status_code in (200, 204)
    assert "event-stream" in events.headers.get("Content-Type", "")
