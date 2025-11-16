# PT-10/PT-15 alternate API smoke (importorskip)
import pytest
from uuid import uuid4

api = pytest.importorskip("api", reason="API app not found")

pytestmark = pytest.mark.unit


def test_health_ok():
    c = api.app.test_client()
    r = c.get("/api/stats")
    assert r.status_code in (200, 401, 403)  # if auth required, gating is OK


def test_block_rejects_bad_ip():
    c = api.app.test_client()
    api.REQUIRE_AUTH = False
    r = c.post("/api/blocks", json={"ip": "hello", "reason": "bad"})
    assert r.status_code == 400
    body = r.get_json() or {}
    assert body.get("error") == "bad_ip"

    r_unblock = c.post("/api/unblock", json={"ip": "hello"})
    assert r_unblock.status_code == 400
    assert (r_unblock.get_json() or {}).get("error") == "bad_ip"

    r_trust = c.post("/api/trusted", json={"ip": "hello"})
    assert r_trust.status_code == 400
    assert (r_trust.get_json() or {}).get("error") == "bad_ip"


def _rand_user(prefix="user"):
    return f"{prefix}_{uuid4().hex[:10]}"


def test_register_creates_user_and_allows_login():
    c = api.app.test_client()
    api.REQUIRE_AUTH = False
    username = _rand_user()
    password = "secret123"

    r = c.post("/api/auth/register", json={"username": username, "password": password})
    assert r.status_code == 201
    body = r.get_json() or {}
    assert body.get("ok") is True
    assert body.get("user") == username
    assert body.get("token")

    r_login = c.post(
        "/api/auth/login", json={"username": username, "password": password}
    )
    assert r_login.status_code == 200
    assert (r_login.get_json() or {}).get("ok") is True


def test_register_duplicate_user_rejected():
    c = api.app.test_client()
    api.REQUIRE_AUTH = False
    username = _rand_user("dup")
    password = "hunter22"

    first = c.post(
        "/api/auth/register", json={"username": username, "password": password}
    )
    assert first.status_code == 201
    second = c.post(
        "/api/auth/register", json={"username": username, "password": password}
    )
    assert second.status_code == 409
    assert (second.get_json() or {}).get("error") == "user_exists"


def test_reset_password_updates_credentials():
    c = api.app.test_client()
    api.REQUIRE_AUTH = False
    username = _rand_user("reset")
    password = "firstpass"

    r = c.post("/api/auth/register", json={"username": username, "password": password})
    assert r.status_code == 201

    new_password = "secondpass"
    r_reset = c.post(
        "/api/auth/reset-password",
        json={"username": username, "password": new_password},
    )
    assert r_reset.status_code == 200
    assert (r_reset.get_json() or {}).get("ok") is True

    r_login = c.post(
        "/api/auth/login", json={"username": username, "password": new_password}
    )
    assert r_login.status_code == 200
    assert (r_login.get_json() or {}).get("ok") is True
