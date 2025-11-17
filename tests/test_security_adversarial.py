"""Adversarial security tests that exercise API validation and model hardening."""

from __future__ import annotations

import html
import importlib
import os
import pathlib
import pickle
import sqlite3
from datetime import timedelta

import pytest

import anomaly_detector


_MALICIOUS_PAYLOADS = [
    "' OR 1=1--",
    "127.0.0.1; rm -rf /",
    "1.2.3.4 && whoami",
    "admin'--",
    "1' UNION SELECT NULL--",
    "1; DELETE FROM blocks WHERE 1=1--",
    "0.0.0.0 | reboot",
]


_ORIG_MODEL_DIR = anomaly_detector.DEFAULT_MODEL_DIR


@pytest.mark.security
def test_block_endpoint_rejects_injection_payloads(api_harness):
    """Attempted SQL/command injection strings must be rejected as invalid IPs."""
    make_client = api_harness["make_client"]
    webdb = api_harness["webdb"]

    client = make_client()
    for payload in _MALICIOUS_PAYLOADS:
        resp = client.post("/api/block", json={"ip": payload, "reason": "attack"})
        assert resp.status_code == 400
        body = resp.get_json()
        assert body["error"] in {"bad_ip", "trusted_ip"}

    rows = webdb.list_blocks(limit=20)
    malicious = {row["ip"] for row in rows if row["ip"] in _MALICIOUS_PAYLOADS}
    assert not malicious
    client.close()


@pytest.mark.security
def test_trusted_ip_api_sanitizes_notes(api_harness):
    """Trusted IP management should persist attacker controlled notes safely."""
    make_client = api_harness["make_client"]

    client = make_client()
    resp = client.post(
        "/api/trusted",
        json={"ip": "203.0.113.77", "note": "<script>alert('x')</script>"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True

    listing = client.get("/api/trusted")
    assert listing.status_code == 200
    entries = [
        entry
        for entry in listing.get_json().get("items", [])
        if entry["ip"] == "203.0.113.77"
    ]
    assert entries
    expected_note = html.escape("<script>alert('x')</script>", quote=True)
    assert entries[0]["note"] == expected_note
    client.close()


@pytest.mark.security
def test_alert_endpoint_preserves_malicious_labels(api_harness):
    """Alerts containing attacker controlled strings must be returned safely."""
    make_client = api_harness["make_client"]
    webdb = api_harness["webdb"]

    label = "<svg onload=alert('xss')>"
    alert_id = webdb.add_alert(
        src_ip="203.0.113.5",
        label=label,
        severity="high",
        kind="security-test",
    )

    client = make_client()
    response = client.get("/api/alerts?limit=5")
    client.close()

    assert response.status_code == 200
    alerts = response.get_json()["items"]
    stored = next((row for row in alerts if row.get("id") == alert_id), None)
    assert stored is not None
    assert stored["label"] == label


@pytest.mark.security
def test_authentication_enforced_when_required(monkeypatch, request):
    """When REQUIRE_AUTH=1 the API should reject anonymous access until login."""
    monkeypatch.setenv("REQUIRE_AUTH", "1")
    harness = request.getfixturevalue("api_harness")
    make_client = harness["make_client"]

    client = make_client()
    resp = client.get("/api/alerts")
    assert resp.status_code == 401

    login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    assert login.status_code == 200
    assert login.get_json().get("ok") is True

    authed = client.get("/api/alerts")
    assert authed.status_code == 200
    assert authed.get_json().get("ok") is True
    client.close()


@pytest.mark.security
def test_login_brute_force_lockout(api_harness, monkeypatch):
    """Repeated failed logins should eventually lock the account."""
    harness = api_harness["api"]
    make_client = api_harness["make_client"]
    monkeypatch.setattr(harness, "LOCK_AFTER", 3)
    harness._LOCKS.clear()

    client = make_client()
    try:
        for _ in range(3):
            resp = client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "not-it"},
            )
            assert resp.status_code == 403
            assert resp.get_json()["error"] == "invalid"

        locked = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "still-wrong"},
        )
        assert locked.status_code == 403
        body = locked.get_json()
        assert body["error"] == "locked"
        assert "locked_until" in body
    finally:
        client.close()
        harness._clear_failures("admin")
        harness._LOCKS.clear()


@pytest.mark.security
def test_model_loader_blocks_path_traversal():
    """Model loader must refuse paths that escape the configured directory."""
    detector = anomaly_detector.AnomalyDetector()
    dangerous = pathlib.Path("../evil.pkl")
    with pytest.raises(ValueError):
        detector.load(str(dangerous))


@pytest.mark.security
def test_model_loader_rejects_corrupt_bundle(monkeypatch, tmp_path):
    """Corrupt model bundles should be rejected during load."""
    monkeypatch.setenv("MODEL_DIR", str(tmp_path))
    reloaded = importlib.reload(anomaly_detector)
    try:
        detector = reloaded.AnomalyDetector()
        corrupt = tmp_path / "broken.pkl"
        corrupt.write_text("not a joblib payload")
        with pytest.raises(Exception):
            detector.load("broken.pkl")
    finally:
        monkeypatch.setenv("MODEL_DIR", str(_ORIG_MODEL_DIR))
        importlib.reload(anomaly_detector)


@pytest.mark.security
def test_malicious_pickle_detection(tmp_path):
    """Model loader should refuse pickle payloads with dangerous reducers."""

    class Exploit:
        def __reduce__(self):
            return (os.system, ("echo pwned",))

    payload_path = tmp_path / "evil.pkl"
    with payload_path.open("wb") as fh:
        pickle.dump(Exploit(), fh)

    detector = anomaly_detector.AnomalyDetector()

    with pytest.raises(anomaly_detector.SecurityError):
        detector.load_model(str(payload_path))


@pytest.mark.security
def test_block_endpoint_rate_limit_thwarts_burst(api_harness, monkeypatch):
    """Rapid block requests from a single client should trigger the rate limiter."""
    harness_api = api_harness["api"]
    harness_api._RATE_LIMITER.clear()
    monkeypatch.setitem(harness_api.RATE_LIMITS, "block", (3, 60.0))
    client = api_harness["make_client"]()

    for i in range(3):
        resp = client.post(
            "/api/block",
            json={"ip": f"203.0.113.{10 + i}", "reason": "burst"},
        )
        assert resp.status_code == 200

    denied = client.post(
        "/api/block",
        json={"ip": "203.0.113.200", "reason": "burst"},
    )
    assert denied.status_code == 429
    body = denied.get_json()
    assert body["error"] == "rate_limited"

    # Changing the reason should not bypass the limiter for the same client.
    bypass_attempt = client.post(
        "/api/block",
        json={"ip": "203.0.113.201", "reason": "different"},
    )
    assert bypass_attempt.status_code == 429

    client.close()
    harness_api._RATE_LIMITER.clear()


@pytest.mark.security
def test_trusted_endpoint_rate_limit_and_disk_full(api_harness, monkeypatch):
    """Trusted IP writes should surface disk full errors and respect throttling."""
    harness_api = api_harness["api"]
    harness_api._RATE_LIMITER.clear()
    monkeypatch.setitem(harness_api.RATE_LIMITS, "trusted", (2, 60.0))
    client = api_harness["make_client"]()

    for suffix in range(2):
        resp = client.post(
            "/api/trusted",
            json={"ip": f"203.0.113.{50 + suffix}", "note": "ok"},
        )
        assert resp.status_code == 200

    rate_limited = client.post(
        "/api/trusted",
        json={"ip": "203.0.113.99", "note": "overflow"},
    )
    assert rate_limited.status_code == 429
    assert rate_limited.get_json()["error"] == "rate_limited"

    def boom(*args, **kwargs):
        raise sqlite3.OperationalError("database or disk is full")

    monkeypatch.setattr(harness_api.webdb, "upsert_trusted_ip", boom)
    harness_api._RATE_LIMITER.clear()

    disk_full = client.post(
        "/api/trusted",
        json={"ip": "203.0.113.150", "note": "boom"},
    )
    assert disk_full.status_code == 507
    assert disk_full.get_json()["error"] == "disk_full"

    client.close()
    harness_api._RATE_LIMITER.clear()


@pytest.mark.security
def test_expired_or_forged_tokens_are_rejected(monkeypatch, request):
    """Bearer tokens that expire or are fabricated must not grant access."""

    monkeypatch.setenv("REQUIRE_AUTH", "1")
    harness = request.getfixturevalue("api_harness")
    api_mod = harness["api"]
    api_mod.REQUIRE_AUTH = True
    with api_mod._TOKENS_LOCK:
        api_mod._TOKENS.clear()

    client = harness["make_client"]()

    try:
        login = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "admin"},
        )
        assert login.status_code == 200
        token = login.get_json()["token"]

        headers = {"Authorization": f"Bearer {token}"}
        baseline = client.get("/api/alerts", headers=headers)
        assert baseline.status_code == 200

        with api_mod._TOKENS_LOCK:
            meta = api_mod._TOKENS[token]
            meta["expires_at"] = api_mod._utcnow() - timedelta(seconds=1)

        expired = client.get("/api/alerts", headers=headers)
        assert expired.status_code == 401
        assert expired.get_json().get("error") == "expired"

        forged_token = "deadbeef" * 8
        forged = client.get(
            "/api/alerts",
            headers={"Authorization": f"Bearer {forged_token}"},
        )
        assert forged.status_code == 401
        assert forged.get_json().get("error") in {"invalid", "unauthorized"}

    finally:
        client.close()
        with api_mod._TOKENS_LOCK:
            api_mod._TOKENS.clear()
