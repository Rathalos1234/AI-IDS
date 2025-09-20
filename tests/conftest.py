import time
import pandas as pd
import pytest
import random


def build_packets(
    n=10,
    *,
    start_ts=None,
    src="10.0.0.2",
    dst="1.2.3.4",
    proto=6,
    dport=80,
    sport=50000,
    jitter=0.01,
):
    """Return a list[dict] representing simplified packets for PacketProcessor."""
    if start_ts is None:
        start_ts = time.time()
    pkts = []
    ts = start_ts
    for i in range(n):
        pkts.append(
            {
                "timestamp": ts,
                "src_ip": src,
                "dest_ip": dst,
                "protocol": proto,
                "packet_size": 100 + (i % 200),
                "sport": sport,
                "dport": dport if isinstance(dport, int) else dport(i),
            }
        )
        ts += jitter
    return pkts


@pytest.fixture
def df_two_way():
    """Small, mixed-direction DataFrame of 'packets' for feature engineering tests."""
    now = time.time()
    a = build_packets(
        3,
        start_ts=now - 1,
        src="10.0.0.2",
        dst="8.8.8.8",
        proto=6,
        dport=80,
        sport=55555,
        jitter=0.2,
    )
    b = build_packets(
        2,
        start_ts=now - 0.2,
        src="8.8.8.8",
        dst="10.0.0.2",
        proto=17,
        dport=53000,
        sport=53,
        jitter=0.2,
    )
    return pd.DataFrame(a + b)


try:
    import numpy as np
except Exception:
    np = None


@pytest.fixture(autouse=True)
def _seed_everything():
    random.seed(1337)
    if np is not None:
        np.random.seed(1337)
    yield
