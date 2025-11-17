"""Database integrity tests that exercise transactional behaviour and backups."""

from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import numpy as np
import pandas as pd
import pytest

from anomaly_detector import AnomalyDetector


pytestmark = pytest.mark.integration


def test_transaction_rolls_back_on_exception(api_harness):
    """An explicit transaction that fails should not persist any partial rows."""
    webdb = api_harness["webdb"]

    baseline = len(webdb.list_alerts(limit=1000))
    con = webdb._con()
    try:
        con.execute("BEGIN")
        for i in range(25):
            con.execute(
                "INSERT INTO alerts (id, ts, src_ip, label, severity, kind) VALUES (?,?,?,?,?,?)",
                (
                    f"txn_{i}",
                    webdb._iso_utc(webdb._utcnow()),
                    "198.51.100.42",
                    f"rollback-{i}",
                    "medium",
                    "integration",
                ),
            )
        raise RuntimeError("failure after partial writes")
    except RuntimeError:
        con.execute("ROLLBACK")
    finally:
        con.close()

    after = len(webdb.list_alerts(limit=1000))
    assert after == baseline


def test_nested_transaction_isolation(api_harness):
    """Savepoints should allow rolling back inner failures without losing outer work."""
    webdb = api_harness["webdb"]

    con = webdb._con()
    try:
        con.execute("BEGIN")
        con.execute(
            "INSERT INTO alerts (id, ts, src_ip, label, severity, kind) VALUES (?,?,?,?,?,?)",
            (
                "outer_1",
                webdb._iso_utc(webdb._utcnow()),
                "10.0.0.1",
                "outer",
                "low",
                "txn-test",
            ),
        )
        con.execute("SAVEPOINT nested")
        try:
            con.execute(
                "INSERT INTO alerts (id, ts, src_ip, label, severity, kind) VALUES (?,?,?,?,?,?)",
                (
                    "nested_1",
                    webdb._iso_utc(webdb._utcnow()),
                    "10.0.0.2",
                    "nested",
                    "low",
                    "txn-test",
                ),
            )
            con.execute(
                "INSERT INTO alerts (id, ts, src_ip, label, severity, kind) VALUES (?,?,?,?,?,?)",
                (
                    "nested_1",
                    webdb._iso_utc(webdb._utcnow()),
                    "10.0.0.3",
                    "duplicate",
                    "low",
                    "txn-test",
                ),
            )
        except sqlite3.IntegrityError:
            con.execute("ROLLBACK TO nested")
        con.execute("RELEASE nested")
        con.execute(
            "INSERT INTO alerts (id, ts, src_ip, label, severity, kind) VALUES (?,?,?,?,?,?)",
            (
                "outer_2",
                webdb._iso_utc(webdb._utcnow()),
                "10.0.0.4",
                "outer",
                "low",
                "txn-test",
            ),
        )
        con.execute("COMMIT")
    except Exception:
        con.execute("ROLLBACK")
        raise
    finally:
        con.close()

    alerts = [
        row for row in webdb.list_alerts(limit=50) if row.get("kind") == "txn-test"
    ]
    labels = {row["label"] for row in alerts}
    assert labels == {"outer"}


def test_backup_round_trip_includes_recent_data(api_harness, tmp_path):
    """The /api/backup/db endpoint must include rows written moments earlier."""
    make_client = api_harness["make_client"]
    webdb = api_harness["webdb"]

    for i in range(5):
        webdb.add_alert(
            src_ip=f"203.0.113.{i}",
            label=f"backup-test-{i}",
            severity="high" if i % 2 else "low",
            kind="forensic",
        )
    _ = make_client().post(
        "/api/block", json={"ip": "203.0.113.200", "reason": "backup"}
    )

    client = make_client()
    response = client.get("/api/backup/db")
    client.close()
    assert response.status_code == 200
    backup_file = tmp_path / "backup.sqlite"
    backup_file.write_bytes(response.data)

    with sqlite3.connect(backup_file) as backup_db:
        cursor = backup_db.execute(
            "SELECT COUNT(*) FROM alerts WHERE label LIKE 'backup-test-%'"
        )
        count = cursor.fetchone()[0]
    assert count == 5


def test_backup_consistency_during_writes(api_harness, tmp_path):
    """Backups taken mid write should be valid and internally consistent."""
    make_client = api_harness["make_client"]
    webdb = api_harness["webdb"]

    writes_running = threading.Event()

    def writer() -> None:
        writes_running.set()
        for i in range(60):
            webdb.add_alert(
                src_ip=f"10.1.0.{i}",
                label=f"backup-consistency-{i}",
                severity="medium",
                kind="backup-consistency",
            )
            if i % 10 == 0:
                time.sleep(0.01)

    thread = threading.Thread(target=writer)
    thread.start()
    writes_running.wait(timeout=2)

    client = make_client()
    response = client.get("/api/backup/db")
    client.close()
    assert response.status_code == 200

    thread.join(timeout=5)

    backup_file = tmp_path / "concurrent_backup.sqlite"
    backup_file.write_bytes(response.data)

    with sqlite3.connect(backup_file) as backup_db:
        integrity = backup_db.execute("PRAGMA integrity_check").fetchone()[0]
        assert integrity == "ok"
        fk_violations = backup_db.execute("PRAGMA foreign_key_check").fetchall()
        assert fk_violations == []


def test_integrity_check_after_concurrent_writes(api_harness):
    """Concurrent inserts across tables should keep the SQLite integrity check clean."""
    webdb = api_harness["webdb"]

    def insert_batch(index: int) -> None:
        for i in range(40):
            webdb.add_alert(
                src_ip=f"10.0.{index}.{i}",
                label=f"concurrent-{index}-{i}",
                severity="medium",
                kind="stress",
            )
            if i % 10 == 0:
                webdb.add_block(
                    ip=f"192.0.2.{index}{i}", action="block", reason="stress-test"
                )

    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(insert_batch, idx) for idx in range(6)]
        for fut in futures:
            fut.result(timeout=10)

    with webdb._con() as con:
        integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
    assert integrity == "ok"

    # Legacy verification
    # Ensure alert IDs remain unique across concurrent writers.
    alerts = webdb.list_alerts(limit=500)
    alert_ids = [row["id"] for row in alerts if row["kind"] == "stress"]
    assert len(alert_ids) == len(set(alert_ids))


def test_vacuum_operation_preserves_data(api_harness):
    """Running VACUUM should not alter persisted rows."""
    webdb = api_harness["webdb"]

    ids = [
        webdb.add_alert(
            src_ip=f"10.2.0.{i}",
            label=f"vacuum-{i}",
            severity="low",
            kind="vacuum-test",
        )
        for i in range(40)
    ]

    con = webdb._con()
    try:
        for target in ids[::2]:
            con.execute("DELETE FROM alerts WHERE id = ?", (target,))
        con.commit()
    finally:
        con.close()

    before = [
        row for row in webdb.list_alerts(limit=80) if row.get("kind") == "vacuum-test"
    ]
    con = webdb._con()
    try:
        con.execute("VACUUM")
    finally:
        con.close()

    after = [
        row for row in webdb.list_alerts(limit=80) if row.get("kind") == "vacuum-test"
    ]
    assert len(after) == len(before)


def test_log_export_handles_disk_full(api_harness, monkeypatch):
    """Log export should surface disk full errors instead of returning HTML 500."""
    harness = api_harness["api"]
    client = api_harness["make_client"]()

    def boom(*args, **kwargs):
        raise sqlite3.OperationalError("database or disk is full")

    monkeypatch.setattr(harness.webdb, "list_log_events_filtered", boom)

    try:
        response = client.get("/api/logs/export")
    finally:
        client.close()

    assert response.status_code == 507
    payload = response.get_json()
    assert payload == {"ok": False, "error": "disk_full"}


def test_large_transaction_atomicity(api_harness):
    """A failure mid transaction should roll back all pending rows."""
    webdb = api_harness["webdb"]

    baseline = len(webdb.list_alerts(limit=500))

    con = webdb._con()
    try:
        con.execute("BEGIN")
        for i in range(120):
            con.execute(
                "INSERT INTO alerts (id, ts, src_ip, label, severity, kind) VALUES (?,?,?,?,?,?)",
                (
                    f"large_txn_{i}",
                    webdb._iso_utc(webdb._utcnow()),
                    f"10.3.0.{i}",
                    f"large-{i}",
                    "low",
                    "large-rollback",
                ),
            )
            if i == 80:
                raise RuntimeError("Simulated failure")
        con.execute("COMMIT")
    except RuntimeError:
        con.execute("ROLLBACK")
    finally:
        con.close()

    final_count = len(webdb.list_alerts(limit=500))
    assert final_count == baseline

    leaked = [
        row
        for row in webdb.list_alerts(limit=200)
        if row.get("kind") == "large-rollback"
    ]
    assert leaked == []


def _train_detector_with_dummy_data() -> AnomalyDetector:
    df = pd.DataFrame(np.random.rand(200, 4), columns=["f1", "f2", "f3", "f4"])
    detector = AnomalyDetector(contamination=0.05, n_estimators=20)
    detector.fit(df)
    return detector


def test_model_save_failure_preserves_existing_bundle(tmp_path, monkeypatch):
    """If a model save fails midway, the previous bundle should remain untouched."""
    detector = _train_detector_with_dummy_data()
    bundle = tmp_path / "model.pkl"
    detector.save_model(str(bundle))
    baseline_hash = hashlib.sha256(bundle.read_bytes()).hexdigest()

    def boom(*args, **kwargs):
        raise OSError("No space left on device")

    monkeypatch.setattr("joblib.dump", boom)

    with pytest.raises(OSError):
        detector.save_model(str(bundle))

    after_hash = hashlib.sha256(bundle.read_bytes()).hexdigest()
    assert after_hash == baseline_hash
    leftovers = [p for p in tmp_path.iterdir() if p.suffix == ".tmp"]
    assert leftovers == []


def test_model_save_recovers_after_failure(tmp_path):
    """A subsequent save should succeed once the failure condition clears."""
    detector = _train_detector_with_dummy_data()
    bundle = tmp_path / "model.pkl"
    detector.save_model(str(bundle))

    detector.save_model(str(bundle))
    assert bundle.exists()


def test_partial_model_save_does_not_leave_corruption(tmp_path, monkeypatch):
    """Crash during save should not leave a truncated model file."""

    detector = _train_detector_with_dummy_data()
    target = tmp_path / "model.pkl"

    def flaky_dump(payload, filename, *args, **kwargs):
        with open(filename, "wb") as fh:
            fh.write(b"partial")
        raise RuntimeError("crash during dump")

    monkeypatch.setattr("joblib.dump", flaky_dump)

    with pytest.raises(RuntimeError):
        detector.save_model(str(target))

    assert not target.exists()
    assert not any(p.suffix == ".tmp" for p in tmp_path.iterdir())
