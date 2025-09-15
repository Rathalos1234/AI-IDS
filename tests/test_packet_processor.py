import pandas as pd
import pytest

from packet_processor import PacketProcessor

pytestmark = pytest.mark.unit


def test_engineer_features_basic(df_two_way):
    pp = PacketProcessor(window_size=50)
    # Force a known "local" IP for direction checks
    pp._local_ips = {"10.0.0.2"}
    # Use our DataFrame of dict-like packets
    feats, dfp = pp.engineer_features(df_two_way)
    # columns and shape
    assert list(feats.columns) == PacketProcessor.FEATURES
    assert len(feats) == len(df_two_way)
    # basic value checks on computed features
    assert feats["protocol"].isin([6.0, 17.0]).all()
    assert (feats["packet_size_log"] >= 0).all()
    # time_diff should be non-negative and 0 for first row
    assert (feats["time_diff"] >= 0).all()
    assert feats["time_diff"].iloc[0] == pytest.approx(0.0, abs=1e-9)
    # direction: our local src is outbound=1.0, anything else 0.0
    # In this implementation, direction==1.0 when src is local
    assert set(feats["direction"].unique()).issubset({0.0, 1.0})


def test_unique_dports_15s_counts():
    pp = PacketProcessor(window_size=100)
    import time
    import pandas as pd

    base = time.time()

    rows = []
    for i, d in enumerate([22, 22, 80, 443, 8080]):
        rows.append(
            {
                "timestamp": base + i * 1.0,
                "src_ip": "1.2.3.4",
                "dest_ip": "10.0.0.2",
                "protocol": 6,
                "packet_size": 150,
                "sport": 40000 + i,
                "dport": d,
            }
        )
    df = pd.DataFrame(rows)

    # Seed the sliding window so engineer_features can “see” recent packets
    pp.packet_data.extend(df.to_dict("records"))

    feats, _ = pp.engineer_features(pp.get_dataframe())
    assert feats["unique_dports_15s"].iloc[-1] >= 4.0


def test_is_ephemeral_sport_flag():
    pp = PacketProcessor()
    # two packets: one ephemeral sport (>=49152), one not
    df = pd.DataFrame(
        [
            {
                "timestamp": 1.0,
                "src_ip": "10.0.0.2",
                "dest_ip": "8.8.8.8",
                "protocol": 6,
                "packet_size": 100,
                "sport": 55555,
                "dport": 80,
            },
            {
                "timestamp": 2.0,
                "src_ip": "8.8.8.8",
                "dest_ip": "10.0.0.2",
                "protocol": 6,
                "packet_size": 100,
                "sport": 53,
                "dport": 53000,
            },
        ]
    )
    feats, _ = pp.engineer_features(df)
    assert feats["is_ephemeral_sport"].iloc[0] == 1.0
    assert feats["is_ephemeral_sport"].iloc[1] == 0.0
