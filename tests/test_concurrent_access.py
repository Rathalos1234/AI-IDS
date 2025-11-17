"""Integration tests covering concurrent access to the Flask API and database."""

from __future__ import annotations

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor, wait, as_completed
from typing import Dict

import pytest

pytestmark = pytest.mark.integration


def _call_block(make_client, ip: str) -> dict:
    client = make_client()
    try:
        response = client.post("/api/block", json={"ip": ip, "reason": "race-test"})
        return {"status": response.status_code, "body": response.get_json()}
    finally:
        client.close()


def _call_unblock(make_client, ip: str) -> dict:
    client = make_client()
    try:
        response = client.post("/api/unblock", json={"ip": ip, "reason": "race-test"})
        return {"status": response.status_code, "body": response.get_json()}
    finally:
        client.close()


def _call_list(make_client) -> dict:
    client = make_client()
    try:
        response = client.get("/api/blocks?limit=100")
        return {"status": response.status_code, "body": response.get_json()}
    finally:
        client.close()


def test_concurrent_block_requests(api_harness):
    """Multiple block requests against different IPs should succeed in parallel."""
    make_client = api_harness["make_client"]
    webdb = api_harness["webdb"]

    ips = [f"10.0.0.{i}" for i in range(1, 11)]
    barrier = threading.Barrier(len(ips))

    def worker(ip: str) -> dict:
        barrier.wait()
        return _call_block(make_client, ip)

    with ThreadPoolExecutor(max_workers=len(ips)) as executor:
        futures = [executor.submit(worker, ip) for ip in ips]
        results = [f.result(timeout=5) for f in futures]

    assert all(r["status"] == 200 and r["body"]["ok"] for r in results)

    rows = webdb.list_blocks(limit=50)
    seen = {row["ip"] for row in rows if row["action"] == "block"}
    for ip in ips:
        assert ip in seen


def test_race_between_block_and_unblock(api_harness):
    """Concurrent block/unblock operations for the same IP settle on the latest action."""
    make_client = api_harness["make_client"]
    webdb = api_harness["webdb"]

    ip = "203.0.113.200"
    initial = _call_block(make_client, ip)
    assert initial["status"] == 200

    threads = []
    barrier = threading.Barrier(6)

    def block_worker() -> tuple[str, dict]:
        barrier.wait()
        return "block", _call_block(make_client, ip)

    def unblock_worker() -> tuple[str, dict]:
        barrier.wait()
        return "unblock", _call_unblock(make_client, ip)

    with ThreadPoolExecutor(max_workers=6) as executor:
        for _ in range(3):
            threads.append(executor.submit(block_worker))
            threads.append(executor.submit(unblock_worker))
        outcomes = [future.result(timeout=5) for future in as_completed(threads)]

    successful_actions: list[str] = []
    for action, result in outcomes:
        assert result["status"] in {200, 400}
        assert "ok" in result["body"]
        if result["status"] == 200:
            successful_actions.append(action)

    assert successful_actions, "Expected at least one successful block/unblock response"
    last_action = successful_actions[-1]

    with sqlite3.connect(webdb.DB) as con:
        con.row_factory = sqlite3.Row
        latest = con.execute(
            "SELECT action FROM blocks WHERE ip = ? ORDER BY rowid DESC LIMIT 1",
            (ip,),
        ).fetchone()

    assert latest is not None
    assert latest["action"] == last_action


def test_list_blocks_consistency_under_load(api_harness):
    """Listing blocks while writes occur should never return HTTP errors or duplicates."""
    make_client = api_harness["make_client"]
    webdb = api_harness["webdb"]

    ips_to_add = [f"198.51.100.{i}" for i in range(1, 8)]
    barrier = threading.Barrier(len(ips_to_add) + 1)

    def writer(ip: str):
        barrier.wait()
        return _call_block(make_client, ip)

    def reader():
        barrier.wait()
        snapshot = _call_list(make_client)
        assert snapshot["status"] == 200
        active = snapshot["body"].get("active", [])
        assert isinstance(active, list)
        ips = [entry.get("ip") for entry in active]
        assert len(ips) == len(set(ips))
        return snapshot

    with ThreadPoolExecutor(max_workers=len(ips_to_add) + 1) as executor:
        futures = [executor.submit(writer, ip) for ip in ips_to_add]
        futures.append(executor.submit(reader))
        wait(futures, timeout=10)
        results = [f.result(timeout=1) for f in futures]

    writer_results = results[:-1]
    read_result = results[-1]
    assert all(r["status"] == 200 for r in writer_results)
    observed_ips = {row["ip"] for row in read_result["body"].get("active", [])}
    assert observed_ips.issubset({row["ip"] for row in webdb.list_blocks(limit=50)})


def test_webdb_block_counts_monotonic_during_concurrent_writes(api_harness):
    """Keep the low-level monotonic read assertion from the legacy suite."""
    webdb = api_harness["webdb"]

    to_insert = [f"172.16.0.{i}" for i in range(20)]
    barrier = threading.Barrier(2)
    query_counts: list[int] = []

    def insert_all() -> None:
        barrier.wait()
        for ip in to_insert:
            webdb.add_block(ip=ip, action="block", reason="legacy-check")

    def read_repeatedly() -> None:
        barrier.wait()
        for _ in range(30):
            rows = webdb.list_blocks(limit=50)
            query_counts.append(len(rows))

    with ThreadPoolExecutor(max_workers=2) as executor:
        executor.submit(insert_all)
        executor.submit(read_repeatedly)

    assert query_counts, "Expected read loop to capture block counts"
    for earlier, later in zip(query_counts, query_counts[1:]):
        assert later >= earlier, (
            "Block listing should not move backwards during inserts"
        )


def test_concurrent_alert_creation_consistency(api_harness):
    """Simultaneous alert creation from multiple sources maintains consistency."""
    webdb = api_harness["webdb"]

    def create_alerts(thread_id: int, count: int) -> list[str]:
        created: list[str] = []
        for i in range(count):
            created.append(
                webdb.add_alert(
                    src_ip=f"10.{thread_id}.0.{i}",
                    label=f"thread-{thread_id}-{i}",
                    severity="high" if i % 2 == 0 else "low",
                    kind="concurrent-test",
                )
            )
        return created

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(create_alerts, tid, 12) for tid in range(4)]
        alert_ids = []
        for future in as_completed(futures):
            alert_ids.extend(future.result(timeout=5))

    assert len(alert_ids) == len(set(alert_ids)), "Duplicate alert IDs detected"

    persisted = [
        row
        for row in webdb.list_alerts(limit=200)
        if row.get("kind") == "concurrent-test"
    ]
    assert len(persisted) == len(alert_ids), "Not all concurrent alerts persisted"


def test_concurrent_database_read_write_isolation(api_harness):
    """Readers must not observe partially committed transactions."""
    webdb = api_harness["webdb"]

    write_started = threading.Event()
    midpoint_reached = threading.Event()
    allow_commit = threading.Event()
    writer_done = threading.Event()

    def slow_batch_write() -> None:
        con = webdb._con()
        try:
            con.execute("BEGIN")
            write_started.set()
            for i in range(20):
                con.execute(
                    "INSERT INTO alerts (id, ts, src_ip, label, severity, kind) VALUES (?,?,?,?,?,?)",
                    (
                        f"batch_{i}",
                        webdb._iso_utc(webdb._utcnow()),
                        "192.0.2.10",
                        f"batch-{i}",
                        "low",
                        "batch-write",
                    ),
                )
                if i == 10:
                    midpoint_reached.set()
                    allow_commit.wait(timeout=2)
            con.execute("COMMIT")
        except Exception:
            con.execute("ROLLBACK")
            raise
        finally:
            con.close()
            writer_done.set()

    def concurrent_reader() -> Dict[str, int]:
        write_started.wait(timeout=2)
        midpoint_reached.wait(timeout=2)
        snapshot = webdb.list_alerts(limit=40)
        visible = [row for row in snapshot if row.get("kind") == "batch-write"]
        allow_commit.set()
        writer_done.wait(timeout=2)
        final = [
            row
            for row in webdb.list_alerts(limit=40)
            if row.get("kind") == "batch-write"
        ]
        return {"mid_commit": len(visible), "post_commit": len(final)}

    with ThreadPoolExecutor(max_workers=2) as executor:
        writer_future = executor.submit(slow_batch_write)
        reader_future = executor.submit(concurrent_reader)
        reader_counts = reader_future.result(timeout=5)
        writer_future.result(timeout=5)

    assert reader_counts["mid_commit"] in {0}, "Reader saw partial transaction"
    assert reader_counts["post_commit"] == 20, "Expected all rows after commit"


def test_api_and_database_concurrent_modifications(api_harness):
    """Concurrent API and direct database writes should keep state consistent."""
    make_client = api_harness["make_client"]
    webdb = api_harness["webdb"]

    test_ip = "172.16.0.1"

    def api_worker() -> None:
        client = make_client()
        try:
            for _ in range(6):
                client.post("/api/block", json={"ip": test_ip, "reason": "api-test"})
                client.post("/api/unblock", json={"ip": test_ip, "reason": "api-test"})
        finally:
            client.close()

    def database_worker() -> None:
        for i in range(6):
            webdb.add_block(ip=f"172.16.1.{i}", action="block", reason="db-test")
            webdb.add_alert(
                src_ip=f"172.16.1.{i}",
                label=f"db-alert-{i}",
                severity="medium",
                kind="db-test",
            )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(fn) for fn in (api_worker, database_worker)]
        for fut in futures:
            fut.result(timeout=10)

    with webdb._con() as con:
        integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
        assert integrity == "ok"

    recent_blocks = [
        row for row in webdb.list_blocks(limit=30) if "172.16.1." in row["ip"]
    ]
    assert len(recent_blocks) == 6

    recent_alerts = [
        row for row in webdb.list_alerts(limit=30) if row.get("kind") == "db-test"
    ]
    assert len(recent_alerts) == 6


def test_alert_generation_during_vacuum(api_harness):
    """Alert inserts should succeed even when a VACUUM is running in parallel."""
    webdb = api_harness["webdb"]

    start_vacuum = threading.Event()
    vacuum_running = threading.Event()
    vacuum_done = threading.Event()
    inserted_ids: list[str] = []
    writer_errors: list[Exception] = []

    def writer() -> None:
        try:
            for i in range(60):
                inserted_ids.append(
                    webdb.add_alert(
                        src_ip=f"198.51.100.{i}",
                        label=f"vacuum-race-{i}",
                        severity="medium" if i % 2 else "low",
                        kind="vacuum-race",
                    )
                )
                if i == 5:
                    start_vacuum.set()
                    vacuum_running.wait(timeout=2)
        except Exception as exc:  # pragma: no cover - defensive guard
            writer_errors.append(exc)

    def run_vacuum() -> None:
        if not start_vacuum.wait(timeout=2):
            return
        with webdb._con() as con:
            vacuum_running.set()
            con.execute("VACUUM")
        vacuum_done.set()

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(writer), executor.submit(run_vacuum)]
        for future in futures:
            future.result(timeout=10)

    assert not writer_errors, f"Unexpected writer errors: {writer_errors!r}"
    assert vacuum_done.is_set(), "VACUUM thread did not complete"

    persisted = [
        row for row in webdb.list_alerts(limit=120) if row.get("kind") == "vacuum-race"
    ]
    assert len(persisted) == len(inserted_ids) == 60
    persisted_ids = {row["id"] for row in persisted}
    assert set(inserted_ids) == persisted_ids


def test_thundering_herd_on_startup(api_harness):
    """A burst of clients hitting the API simultaneously should all succeed."""
    make_client = api_harness["make_client"]

    barrier = threading.Barrier(8)

    def eager_client() -> bool:
        barrier.wait()
        client = make_client()
        try:
            responses = [
                client.get("/api/alerts?limit=5"),
                client.get("/api/blocks?limit=5"),
                client.get("/api/trusted"),
            ]
            return all(resp.status_code == 200 for resp in responses)
        finally:
            client.close()

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(eager_client) for _ in range(8)]
        results = [future.result(timeout=5) for future in futures]

    assert all(results)


@pytest.mark.slow
def test_concurrent_backup_and_modifications(api_harness, tmp_path):
    """Taking a backup mid-write should still yield a valid SQLite snapshot."""
    make_client = api_harness["make_client"]
    webdb = api_harness["webdb"]

    start_backup = threading.Event()

    def modifier() -> None:
        start_backup.set()
        for i in range(30):
            webdb.add_alert(
                src_ip=f"10.99.0.{i}",
                label=f"during-backup-{i}",
                severity="low",
                kind="backup-test",
            )
            if i % 5 == 0:
                webdb.add_block(
                    ip=f"10.99.1.{i}",
                    action="block",
                    reason="backup-test",
                )

    def fetch_backup() -> bytes:
        start_backup.wait(timeout=2)
        client = make_client()
        try:
            resp = client.get("/api/backup/db")
            assert resp.status_code == 200
            return resp.data
        finally:
            client.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        writer_future = executor.submit(modifier)
        backup_future = executor.submit(fetch_backup)
        backup_bytes = backup_future.result(timeout=10)
        writer_future.result(timeout=10)

    backup_file = tmp_path / "snapshot.sqlite"
    backup_file.write_bytes(backup_bytes)

    with sqlite3.connect(backup_file) as backup_db:
        integrity = backup_db.execute("PRAGMA integrity_check").fetchone()[0]
        assert integrity == "ok"
        counts = backup_db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        assert counts >= 0
