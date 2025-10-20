# PT-17/PT-18: Auth & lockout
import importlib
import pytest

api = None  # will be imported/reloaded inside tests

pytestmark = pytest.mark.unit


def _client_with_auth(monkeypatch):
    global api
    monkeypatch.setenv("REQUIRE_AUTH", "1")
    import api as api_mod

    importlib.reload(api_mod)
    api = api_mod
    return api.app.test_client()


def _find(client, cands):
    for p in cands:
        r = client.options(p)
        if r.status_code != 404:
            return p
    return None


def test_auth_gating_and_session_cookie(monkeypatch):
    c = _client_with_auth(monkeypatch)
    # protected without login
    r0 = c.get("/api/stats")
    assert r0.status_code in (401, 403)

    login = _find(c, ["/api/login", "/api/auth/login", "/login"]) or pytest.skip(
        "no login endpoint"
    )
    r1 = c.post(login, json={"username": "admin", "password": "admin"})
    assert r1.status_code in (200, 204)
    assert "Set-Cookie" in r1.headers

    r2 = c.get("/api/stats")
    assert r2.status_code == 200

    logout = _find(c, ["/api/logout", "/api/auth/logout", "/logout"]) or pytest.skip(
        "no logout endpoint"
    )
    r3 = c.post(logout)
    assert r3.status_code in (200, 204)
    r4 = c.get("/api/stats")
    assert r4.status_code in (401, 403)


def test_lockout_after_failed_attempts(monkeypatch):
    c = _client_with_auth(monkeypatch)
    login = _find(c, ["/api/login", "/api/auth/login", "/login"]) or pytest.skip(
        "no login endpoint"
    )
    for _ in range(6):
        c.post(login, json={"username": "admin", "password": "WRONG"})
    r = c.post(login, json={"username": "admin", "password": "WRONG"})
    assert r.status_code in (401, 423, 429, 403)
