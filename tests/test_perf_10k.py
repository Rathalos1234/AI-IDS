# tests/test_perf_10k.py
import logging
import time
import tracemalloc
import pytest
import pandas as pd
from packet_processor import PacketProcessor
from anomaly_detector import AnomalyDetector

TARGET_SECONDS = 3.0  # start generous for S1; tighten in S2
TARGET_MB = 350

pytestmark = [pytest.mark.perf, pytest.mark.slow]


LOGGER = logging.getLogger(__name__)


def _make_df(n=10_000):
    rows, t0 = [], time.time()
    for i in range(n):
        rows.append(
            {
                "timestamp": t0 + i * 0.001,
                "src_ip": "10.0.0.2" if i % 2 == 0 else "8.8.8.8",
                "dest_ip": "8.8.8.8" if i % 2 == 0 else "10.0.0.2",
                "protocol": 6 if i % 3 else 17,
                "packet_size": 100 + (i % 512),
                "sport": 49152 + (i % 1000),
                "dport": 80 if i % 5 else 443,
            }
        )
    return pd.DataFrame(rows)


@pytest.mark.perf
def test_process_10k_under_budget(record_property):
    pp = PacketProcessor(window_size=15_000)
    pp._local_ips = set()
    tracemalloc.start()
    t0 = time.perf_counter()

    df = _make_df()
    feats, _ = pp.engineer_features(df)
    det = AnomalyDetector(contamination=0.05, n_estimators=100, random_state=42)
    det.train(feats)

    elapsed = time.perf_counter() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    peak_mb = peak / (1024 * 1024)
    rows_sec = len(df) / max(elapsed, 1e-9)

    assert elapsed <= TARGET_SECONDS, f"10k took {elapsed:.3f}s > {TARGET_SECONDS}s"
    assert peak_mb <= TARGET_MB, f"Peak {peak_mb:.1f}MB > {TARGET_MB}MB"
    msg = f"rows/sec={rows_sec:.0f}  time={elapsed:.3f}s  peakMB={peak_mb:.1f}"
    LOGGER.info(msg)
    print(msg)
    record_property("perf10k_rows_per_sec", round(rows_sec, 2))
    record_property("perf10k_elapsed_s", round(elapsed, 6))
    record_property("perf10k_peak_mb", round(peak_mb, 3))
