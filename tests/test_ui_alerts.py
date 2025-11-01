"""Backend coverage for Alerts UI manual scenarios."""

from __future__ import annotations
import json
from collections import deque
import pytest
import api

pytestmark = pytest.mark.integration


@pytest.fixture()
def client(monkeypatch, tmp_path):
    """Provide a Flask test client backed by an isolated SQLite database."""

    db_file = tmp_path / "alerts.db"
    monkeypatch.setattr(api.webdb, "DB", db_file)
    api.webdb.init()
    api.app.config.update(TESTING=True)
    api.REQUIRE_AUTH = False
    with api.app.test_client() as client:
        yield client


def test_ui_alerts_01_filter_form_applies_rest_query_params(client, monkeypatch):
    """UI-ALERTS-01 — verify filter inputs propagate to the REST query."""

    captured = {}
    rows = [
        {
            "id": "evt-1",
            "ts": "2025-10-01T04:00:00Z",
            "ip": "198.51.100.9",
            "type": "alert",
            "label": "Suspicious traffic",
            "severity": "high",
            "kind": "ANOMALY",
        }
    ]

    def fake_list_log_events_filtered(*, limit, ip, severity, kind, ts_from, ts_to):
        captured.update(
            {
                "limit": limit,
                "ip": ip,
                "severity": severity,
                "kind": kind,
                "ts_from": ts_from,
                "ts_to": ts_to,
            }
        )
        return rows

    monkeypatch.setattr(
        api.webdb, "list_log_events_filtered", fake_list_log_events_filtered
    )

    resp = client.get(
        "/api/logs",
        query_string={
            "limit": "75",
            "ip": "203.0.113.5",
            "severity": "medium",
            "type": "block",
            "from": "2025-10-01T00:00:00Z",
            "to": "2025-10-02T00:00:00Z",
        },
    )

    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload == {
        "ok": True,
        "items": rows,
    }
    assert captured == {
        "limit": 75,
        "ip": "203.0.113.5",
        "severity": "medium",
        "kind": "block",
        "ts_from": "2025-10-01T00:00:00Z",
        "ts_to": "2025-10-02T00:00:00Z",
    }


@pytest.mark.parametrize(
    "fmt, expected_mimetype",
    [
        ("csv", "text/csv"),
        ("json", "application/json"),
    ],
)
def test_ui_alerts_02_export_buttons_honor_filters(
    client, monkeypatch, fmt, expected_mimetype
):
    """UI-ALERTS-02 — export endpoints reuse the active filter set."""

    captured = {}
    rows = [
        {
            "id": "evt-1",
            "ts": "2025-10-01T04:00:00Z",
            "ip": "198.51.100.9",
            "type": "alert",
            "label": "Suspicious traffic",
            "severity": "high",
            "kind": "ANOMALY",
        },
        {
            "id": "evt-2",
            "ts": "2025-10-01T04:05:00Z",
            "ip": "203.0.113.5",
            "type": "block",
            "label": "block",
            "severity": None,
            "kind": "block",
        },
    ]

    def fake_list_log_events_filtered(*, limit, ip, severity, kind, ts_from, ts_to):
        captured.update(
            {
                "limit": limit,
                "ip": ip,
                "severity": severity,
                "kind": kind,
                "ts_from": ts_from,
                "ts_to": ts_to,
            }
        )
        return rows

    monkeypatch.setattr(
        api.webdb, "list_log_events_filtered", fake_list_log_events_filtered
    )

    resp = client.get(
        "/api/logs/export",
        query_string={
            "format": fmt,
            "limit": "250",
            "ip": "203.0.113.5",
            "severity": "medium",
            "type": "block",
            "from": "2025-10-01T00:00:00Z",
            "to": "2025-10-02T00:00:00Z",
        },
    )

    assert resp.status_code == 200
    assert resp.mimetype == expected_mimetype
    assert captured == {
        "limit": 250,
        "ip": "203.0.113.5",
        "severity": "medium",
        "kind": "block",
        "ts_from": "2025-10-01T00:00:00Z",
        "ts_to": "2025-10-02T00:00:00Z",
    }

    if fmt == "csv":
        body = resp.data.decode("utf-8").strip().splitlines()
        assert body[0].split(",") == [
            "id",
            "ts",
            "ip",
            "type",
            "label",
            "severity",
            "kind",
        ]
        assert len(body) == 3
    else:
        exported = json.loads(resp.data.decode("utf-8"))
        assert exported == rows


def test_ui_alerts_03_realtime_stream_deduplicates(monkeypatch):
    """UI-ALERTS-03 — SSE stream surfaces each alert/block once despite polling cadence."""

    alerts_seq = deque(
        [
            [
                {
                    "id": "alert-1",
                    "ts": "2025-10-01T04:00:00Z",
                    "src_ip": "198.51.100.9",
                    "label": "Suspicious traffic",
                    "severity": "high",
                    "kind": "ANOMALY",
                }
            ],
            [
                {
                    "id": "alert-1",
                    "ts": "2025-10-01T04:00:00Z",
                    "src_ip": "198.51.100.9",
                    "label": "Suspicious traffic",
                    "severity": "high",
                    "kind": "ANOMALY",
                }
            ],
            [
                {
                    "id": "alert-2",
                    "ts": "2025-10-01T04:02:00Z",
                    "src_ip": "203.0.113.5",
                    "label": "Second hit",
                    "severity": "medium",
                    "kind": "SIGNATURE",
                }
            ],
        ]
    )
    blocks_seq = deque(
        [
            [],
            [],
            [
                {
                    "id": "block-1",
                    "ts": "2025-10-01T04:03:00Z",
                    "ip": "203.0.113.5",
                    "action": "block",
                    "reason": "auto",
                }
            ],
        ]
    )

    def fake_list_alerts(limit):
        if alerts_seq:
            return alerts_seq.popleft()
        return []

    def fake_list_blocks(limit):
        if blocks_seq:
            return blocks_seq.popleft()
        return []

    monkeypatch.setattr(api.webdb, "list_alerts", fake_list_alerts)
    monkeypatch.setattr(api.webdb, "list_blocks", fake_list_blocks)

    def fake_sleep(_):
        return None

    monkeypatch.setattr(api.time, "sleep", fake_sleep)

    api.app.config.update(TESTING=True)
    with api.app.test_request_context("/api/events"):
        resp = api.sse_events()
        stream = iter(resp.response)
        next(stream)  # prime the stream_with_context wrapper
        chunks = [next(stream) for _ in range(7)]

    decoded_chunks = []
    for chunk in chunks:
        if isinstance(chunk, memoryview):
            chunk = chunk.tobytes()
        if isinstance(chunk, (bytes, bytearray)):
            chunk = chunk.decode("utf-8")
        decoded_chunks.append(chunk)
    alert_events = [c for c in decoded_chunks if c.startswith("event: alert")]
    block_events = [c for c in decoded_chunks if c.startswith("event: block")]

    assert len(alert_events) == 2  # alert-1 once, alert-2 once
    assert any("alert-1" in event for event in alert_events)
    assert any("alert-2" in event for event in alert_events)
    assert len(block_events) == 1
    assert "block-1" in block_events[0]
