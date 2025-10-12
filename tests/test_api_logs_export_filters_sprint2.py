# PT-20: Logs export & filters
import pytest

api = pytest.importorskip("api", reason="API app not found")

pytestmark = pytest.mark.unit


def test_logs_filters_contract():
    c = api.app.test_client()
    r = c.get(
        "/api/logs?severity=high&type=signature&from=2025-01-01T00:00:00Z&to=2099-01-01T00:00:00Z&ip=192.0.2.1"
    )
    assert r.status_code == 200
    data = r.get_json() or []
    items = data if isinstance(data, list) else data.get("items", [])
    assert isinstance(items, list), f"Unexpected /api/logs shape: {type(data)}"


def test_logs_export_csv_and_json():
    c = api.app.test_client()
    r_csv = c.get("/api/logs/export?format=csv")
    assert r_csv.status_code == 200
    assert "csv" in r_csv.headers.get(
        "Content-Type", ""
    ).lower() or r_csv.data.startswith(b"id,")
    r_json = c.get("/api/logs/export?format=json")
    assert r_json.status_code == 200
    assert "json" in r_json.headers.get("Content-Type", "").lower()
