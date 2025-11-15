import importlib
import os
import random
import sys
import time

import pandas as pd
import pytest


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


# NEW: ensure API/webdb state is clean so tests don't leak into each other
@pytest.fixture(autouse=True, scope="function")
def _reset_api_state():
    """
    Clear trusted IPs, blocks, alerts, and devices before each test.
    Fixes the case where /api/blocks returns 400 (trusted_ip) due to prior state.
    """
    if "api" not in sys.modules:
        yield
        return

    try:
        api_mod = sys.modules["api"]
        c = api_mod.app.test_client()
        resp = c.post("/api/ops/reset")
        # Best-effort; returns 200 when supported (dev), or 501 on minimal webdb.
        # Only ignore 501
        if resp.status_code not in (200, 501):
            import warnings

            warnings.warn(
                f"API reset returned {resp.status_code}, tests may be polluted"
            )
    except ImportError:
        pass
    except Exception as e:
        import warnings

        warnings.warn(f"API reset failed: {e}, tests may be polluted")
    yield


@pytest.fixture
def api_harness(monkeypatch, tmp_path):
    """Provide a fresh Flask test client and isolated SQLite database for API tests."""

    db_path = tmp_path / "api.sqlite"
    monkeypatch.setenv("SQLITE_DB", str(db_path))

    import webdb  # Imported lazily so reload picks up new path

    webdb = importlib.reload(webdb)
    webdb.init()
    webdb.wipe_all()

    if "api" in sys.modules:
        api_mod = importlib.reload(sys.modules["api"])
    else:
        import api as api_mod  # type: ignore[import]

    require_auth = os.environ.get("REQUIRE_AUTH", "0") == "1"
    setattr(api_mod, "REQUIRE_AUTH", require_auth)
    if hasattr(api_mod, "_RATE_LIMITER"):
        getattr(api_mod, "_RATE_LIMITER").clear()

    def make_client():
        client = api_mod.app.test_client()
        if not hasattr(client, "close") and hasattr(client, "__exit__"):

            def _close() -> None:
                client.__exit__(None, None, None)

            setattr(client, "close", _close)
        return client

    yield {"make_client": make_client, "webdb": webdb, "api": api_mod}
