# PT-21: Trusted IPs & temp bans
import pytest

api = pytest.importorskip("api", reason="API app not found")

pytestmark = pytest.mark.unit


def test_trusted_crud_and_temp_ban_contract():
    c = api.app.test_client()
    ip = "198.51.100.9"
    r_add = c.post("/api/trusted", json={"ip": ip, "note": "allowlist"})
    assert r_add.status_code in (200, 201)
    r_list = c.get("/api/trusted")
    assert r_list.status_code == 200
    raw = r_list.get_json()
    # Normalize to a list of IPs or dicts
    if isinstance(raw, dict):
        trusted = raw.get("items", [])
    else:
        trusted = raw or []
    assert isinstance(trusted, list), f"Unexpected /api/trusted shape: {type(raw)}"
    if trusted and isinstance(trusted[0], str):
        assert ip in trusted
    else:
        assert any(isinstance(row, dict) and row.get("ip") == ip for row in trusted)
    r_block = c.post("/api/blocks", json={"ip": ip, "reason": "should fail"})
    assert r_block.status_code in (400, 409, 422)
    ban_ip = "203.0.113.55"
    r_ban = c.post("/api/blocks", json={"ip": ban_ip, "reason": "ttl", "ttl": 5})
    assert r_ban.status_code in (200, 201)
    body = r_ban.get_json() or {}
    assert "expires_at" in body or "ttl" in body
