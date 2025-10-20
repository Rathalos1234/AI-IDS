# IT-10: GUI block → enforcement (API round-trip)
import pytest

api = pytest.importorskip("api", reason="API app not found")

pytestmark = pytest.mark.integration


def test_block_ip_round_trip():
    c = api.app.test_client()
    ip = "203.0.113.42"
    r = c.post("/api/blocks", json={"ip": ip, "reason": "manual"})
    assert r.status_code in (200, 201)
    r2 = c.get("/api/blocks")
    assert r2.status_code == 200
    rows = r2.get_json() or []
    assert any(row.get("ip") == ip for row in rows)
