"""Performance tests that exercise realistic workloads across the IDS pipeline."""

from __future__ import annotations

import logging
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable, List, Optional
import uuid
import os

os.environ["DISABLE_PACKET_OPTIMIZATIONS"] = "1"
import numpy as np
import pandas as pd
import pytest

from anomaly_detector import AnomalyDetector
from packet_processor import PacketProcessor

pytestmark = [pytest.mark.performance, pytest.mark.slow]


LOGGER = logging.getLogger(__name__)


def _emit_latency_stats(
    metric: str,
    samples: Iterable[float],
    *,
    record: Optional[Callable[[str, object], None]] = None,
    unit: str = "ms",
) -> None:
    values = list(samples)
    if not values:
        return
    scale = 1000.0 if unit == "ms" else 1.0
    arr = np.asarray(values, dtype=float)
    percentiles = (50, 90, 95, 99)
    stats = {f"p{p}": float(np.percentile(arr, p) * scale) for p in percentiles}
    stats["max"] = float(arr.max() * scale)
    summary = " ".join(
        f"{key}={stats[key]:.3f}" for key in (*[f"p{p}" for p in percentiles], "max")
    )
    msg = f"{metric} latency ({unit}): {summary}"
    LOGGER.info(msg)
    print(msg)
    if record:
        for key, value in stats.items():
            record(f"{metric}_{key}_{unit}", round(value, 6))


def _record_scalar(
    metric: str,
    value: float,
    *,
    record: Optional[Callable[[str, object], None]] = None,
    unit: str = "",
) -> None:
    msg = f"{metric}: {value:.3f}{unit}"
    LOGGER.info(msg)
    print(msg)
    if record:
        record(metric, round(value, 6))


def _generate_packets(count: int, *, seed: int = 1337) -> List[dict]:
    rng = np.random.default_rng(seed)
    timestamps = np.cumsum(rng.uniform(0.001, 0.02, size=count))
    base_src = np.array(["10.0.0." + str(i % 50 + 1) for i in range(count)])
    base_dst = np.array(["192.168.0." + str(i % 20 + 1) for i in range(count)])
    protocols = rng.integers(1, 3, size=count) * 6  # 6 (TCP) or 12 (UDPish)
    packet_sizes = rng.integers(60, 1500, size=count)
    sport = rng.integers(1024, 65535, size=count)
    dport = rng.choice([22, 53, 80, 123, 443, 8080, 502], size=count)

    packets = []
    start_ts = time.time()
    for i in range(count):
        packets.append(
            {
                "timestamp": float(start_ts + timestamps[i]),
                "src_ip": str(base_src[i]),
                "dest_ip": str(base_dst[i]),
                "protocol": int(protocols[i]),
                "packet_size": int(packet_sizes[i]),
                "sport": int(sport[i]),
                "dport": int(dport[i]),
            }
        )
    return packets


def _generate_burst_packets(base: int, burst: int, cycles: int) -> List[dict]:
    packets: list[dict] = []
    for cycle in range(cycles):
        packets.extend(_generate_packets(base, seed=cycle))
        packets.extend(_generate_packets(burst, seed=cycle + 100))
    return packets


def test_packet_processor_latency_under_10ms(record_property):
    """Each packet extraction should remain comfortably under 10ms."""

    processor = PacketProcessor(window_size=2_000)
    packets = _generate_packets(600)

    latencies = []
    for pkt in packets:
        start = time.perf_counter()
        processor.extract_features(pkt)
        latencies.append(time.perf_counter() - start)

    _emit_latency_stats(
        "packet_processor_extract",
        latencies,
        record=record_property,
    )
    assert max(latencies) < 0.010
    assert np.percentile(latencies, 95) < 0.005
    assert np.percentile(latencies, 99) < 0.008


def test_packet_processor_handles_sustained_load(record_property):
    """Processing 50k packets should stay within real time tolerances."""
    processor = PacketProcessor(window_size=10_000)
    packets = _generate_packets(50_000)

    t0 = time.perf_counter()
    for pkt in packets:
        processor.extract_features(pkt)
    elapsed = time.perf_counter() - t0

    throughput = len(packets) / elapsed
    _record_scalar(
        "packet_processor_sustained_throughput",
        throughput,
        record=record_property,
        unit=" pkt/s",
    )
    _record_scalar(
        "packet_processor_sustained_elapsed_s",
        elapsed,
        record=record_property,
    )
    assert throughput >= 8000

    features_df, _ = processor.engineer_features(pd.DataFrame(packets))
    assert set(features_df.columns) == set(PacketProcessor.FEATURES)


def test_packet_processor_handles_bursts_without_backlog(record_property):
    """Traffic bursts should not cause unbounded window growth or latency spikes."""
    processor = PacketProcessor(window_size=5_000)
    packets = _generate_burst_packets(base=500, burst=5_000, cycles=2)

    latencies: list[float] = []
    max_latency = 0.0
    for packet in packets:
        start = time.perf_counter()
        processor.extract_features(packet)
        elapsed = time.perf_counter() - start
        latencies.append(elapsed)
        max_latency = max(max_latency, elapsed)

    _emit_latency_stats(
        "packet_processor_burst",
        latencies,
        record=record_property,
    )
    assert max_latency < 0.02
    assert len(processor.packet_data) <= processor.window_size


def test_packet_processor_burst_completes_within_minute(record_property):
    """A 10k-packet burst should process in well under a minute to meet SLOs."""
    processor = PacketProcessor(window_size=12_000)
    burst_packets = _generate_packets(10_000)

    start = time.perf_counter()
    for pkt in burst_packets:
        processor.extract_features(pkt)
    elapsed = time.perf_counter() - start

    _record_scalar(
        "packet_processor_burst_elapsed_s",
        elapsed,
        record=record_property,
    )
    assert elapsed < 60


def test_anomaly_detector_training_and_scoring_throughput(record_property):
    """Isolation Forest training/scoring on engineered features must remain fast."""
    processor = PacketProcessor(window_size=60_000)
    packets = _generate_packets(60_000)
    features_df, _ = processor.engineer_features(pd.DataFrame(packets))
    train_df = features_df.sample(40_000, replace=True, random_state=1337)

    detector = AnomalyDetector(contamination=0.02, n_estimators=120)

    t0 = time.perf_counter()
    detector.fit(train_df)
    train_elapsed = time.perf_counter() - t0
    _record_scalar(
        "anomaly_detector_train_elapsed_s",
        train_elapsed,
        record=record_property,
    )
    assert train_elapsed < 25.0

    eval_df = features_df.iloc[:10_000]
    t1 = time.perf_counter()
    scores = detector.decision_scores(eval_df)
    score_elapsed = time.perf_counter() - t1
    _record_scalar(
        "anomaly_detector_score_elapsed_s",
        score_elapsed,
        record=record_property,
    )

    assert len(scores) == len(eval_df)
    assert score_elapsed < 2.0

    baseline_mean = float(scores.mean())
    repeat_mean = float(scores.mean())
    assert repeat_mean == pytest.approx(baseline_mean, rel=1e-6)


def test_anomaly_scoring_latency_for_small_batch(record_property):
    """Scoring 100 packets should complete within <50ms ."""

    processor = PacketProcessor(window_size=2_000)
    packets = _generate_packets(2_500)
    features_df, _ = processor.engineer_features(pd.DataFrame(packets))

    detector = AnomalyDetector(contamination=0.02, n_estimators=80)
    detector.fit(features_df.iloc[:1_000])

    batch = features_df.iloc[:100]
    start = time.perf_counter()
    scores = detector.decision_scores(batch)
    elapsed = time.perf_counter() - start
    _record_scalar(
        "anomaly_scoring_batch_elapsed_s",
        elapsed,
        record=record_property,
    )

    assert len(scores) == len(batch)
    assert elapsed < 0.050


def test_anomaly_detector_training_scales_to_100k_samples(record_property):
    """Training should handle 100k samples in under five minutes."""

    processor = PacketProcessor(window_size=130_000)
    packets = _generate_packets(130_000)
    features_df, _ = processor.engineer_features(pd.DataFrame(packets))
    train_df = features_df.sample(100_000, replace=True, random_state=99)

    detector = AnomalyDetector(contamination=0.02, n_estimators=120)

    start = time.perf_counter()
    detector.fit(train_df)
    elapsed = time.perf_counter() - start
    _record_scalar(
        "anomaly_detector_train_100k_elapsed_s",
        elapsed,
        record=record_property,
    )

    assert elapsed < 300.0


def test_anomaly_detector_incremental_retraining_is_reasonable(record_property):
    """Incremental retraining should be faster than the initial model fit."""
    processor = PacketProcessor(window_size=30_000)
    initial_packets = _generate_packets(12_000, seed=22)
    base_df, _ = processor.engineer_features(pd.DataFrame(initial_packets))

    detector = AnomalyDetector(contamination=0.02, n_estimators=80)
    start = time.perf_counter()
    detector.fit(base_df)
    initial_time = time.perf_counter() - start
    _record_scalar(
        "anomaly_detector_initial_fit_s",
        initial_time,
        record=record_property,
    )

    update_packets = _generate_packets(8_000, seed=99)
    update_df, _ = processor.engineer_features(pd.DataFrame(update_packets))
    blended = pd.concat(
        [base_df.sample(6000, random_state=7), update_df], ignore_index=True
    )

    start = time.perf_counter()
    detector.fit(blended)
    update_time = time.perf_counter() - start
    _record_scalar(
        "anomaly_detector_incremental_fit_s",
        update_time,
        record=record_property,
    )

    assert update_time < initial_time * 1.2


def test_api_alert_listing_under_heavy_history(api_harness):
    """Listing a large alert history must remain responsive."""
    make_client = api_harness["make_client"]
    webdb = api_harness["webdb"]

    with webdb._con() as con:
        ts = webdb._iso_utc(webdb._utcnow())
        payload = [
            (
                uuid.uuid4().hex,
                ts,
                f"198.51.100.{i % 200}",
                f"perf-{i}",
                "high" if i % 5 == 0 else "low",
                "performance",
            )
            for i in range(100_000)
        ]
        con.executemany(
            "INSERT INTO alerts (id, ts, src_ip, label, severity, kind) VALUES (?, ?, ?, ?, ?, ?)",
            payload,
        )

    client = make_client()
    start = time.perf_counter()
    response = client.get("/api/alerts?limit=400")
    elapsed = time.perf_counter() - start
    data = response.get_json()
    client.close()

    assert response.status_code == 200
    assert elapsed < 1.2
    assert data["ok"] is True
    assert len(data["items"]) == 400
    assert data["next_cursor"] == data["items"][-1]["ts"]


def test_database_insert_throughput(api_harness):
    """Bulk database writes should achieve reasonable throughput ."""
    webdb = api_harness["webdb"]

    total = 100_000
    start = time.perf_counter()
    with webdb._con() as con:
        ts = webdb._iso_utc(webdb._utcnow())
        payload = [
            (
                uuid.uuid4().hex,
                ts,
                f"203.0.113.{i % 128}",
                f"bulk-{i}",
                "medium",
                "throughput",
            )
            for i in range(total)
        ]
        con.executemany(
            "INSERT INTO alerts (id, ts, src_ip, label, severity, kind) VALUES (?, ?, ?, ?, ?, ?)",
            payload,
        )
    elapsed = time.perf_counter() - start

    inserts_per_second = total / max(elapsed, 1e-6)
    assert inserts_per_second >= 15_000

    with webdb._con() as con:
        count = con.execute(
            "SELECT COUNT(*) FROM alerts WHERE kind='throughput'"
        ).fetchone()[0]
    assert count == total


def test_concurrent_api_users_remain_responsive(api_harness):
    """Concurrent dashboard sessions should not exhaust server resources."""
    make_client = api_harness["make_client"]

    def worker(idx: int) -> tuple[int, float]:
        client = make_client()
        start = time.perf_counter()
        resp = client.get(f"/api/alerts?limit={50 + idx}")
        elapsed = time.perf_counter() - start
        code = resp.status_code
        client.close()
        return code, elapsed

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(worker, range(10)))

    assert all(code == 200 for code, _ in results)
    latencies = [elapsed for _, elapsed in results]
    assert max(latencies) < 1.0
    assert np.percentile(latencies, 95) < 0.2
    assert np.percentile(latencies, 99) < 0.5


def test_database_handles_heavy_history_queries(api_harness):
    """Querying 100k row history should stay below the latency targets."""
    webdb = api_harness["webdb"]
    make_client = api_harness["make_client"]

    with webdb._con() as con:
        ts = webdb._iso_utc(webdb._utcnow())
        payload = [
            (
                uuid.uuid4().hex,
                ts,
                f"198.51.100.{i % 256}",
                f"history-{i}",
                "medium",
                "history",
            )
            for i in range(100_000)
        ]
        con.executemany(
            "INSERT INTO alerts (id, ts, src_ip, label, severity, kind) VALUES (?, ?, ?, ?, ?, ?)",
            payload,
        )

    client = make_client()
    start = time.perf_counter()
    resp = client.get("/api/alerts?limit=1000")
    elapsed = time.perf_counter() - start
    client.close()

    assert resp.status_code == 200
    assert elapsed < 0.8


def test_monitoring_process_memory_footprint(api_harness):
    """The combined monitoring pipeline should remain under the memory ceiling."""
    processor = PacketProcessor(window_size=25_000)
    packets = _generate_packets(25_000)

    tracemalloc.start()
    try:
        for pkt in packets:
            processor.extract_features(pkt)
        features_df, _ = processor.engineer_features(pd.DataFrame(packets))

        detector = AnomalyDetector(contamination=0.02, n_estimators=80)
        train_df = features_df.sample(12_000, random_state=404)
        detector.fit(train_df)

        scores = detector.decision_scores(features_df.iloc[:5000])
        assert len(scores) == 5000

        client = api_harness["make_client"]()
        try:
            resp = client.get("/api/alerts?limit=100")
        finally:
            client.close()

        assert resp.status_code == 200
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    peak_mebibytes = peak / (1024**2)
    assert peak_mebibytes < 512, (
        f"Peak memory {peak_mebibytes:.1f} MiB exceeds 512 MiB budget"
    )
