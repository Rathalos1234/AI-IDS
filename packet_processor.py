# -*- coding: utf-8 -*-
"""
Packet processing and feature engineering for the AI-Powered IDS.
"""

from __future__ import annotations

from collections import deque
from typing import Deque, Dict, Tuple
import pandas as pd
import numpy as np

try:
    import netifaces  # type: ignore
except Exception:  # pragma: no cover
    netifaces = None

try:
    from scapy.all import IP, TCP, UDP  # type: ignore
except Exception:  # pragma: no cover
    IP = TCP = UDP = object


class PacketProcessor:
    """Transforms raw packets into model-ready features."""

    FEATURES = [
        "protocol",
        "packet_size_log",
        "time_diff",
        "dport",
        "is_ephemeral_sport",
        "unique_dports_15s",
        "direction",
    ]

    def __init__(self, window_size: int = 500) -> None:
        self._local_ips = self._gather_local_ips()
        self._window_size = int(window_size)
        self.packet_data: Deque[Dict] = deque(maxlen=self._window_size)

    def _gather_local_ips(self):
        """Return a set of local IPv4 addresses for direction labeling."""
        ips = set()
        try:
            if netifaces is None:
                return ips
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
                for a in addrs:
                    ip = a.get("addr")
                    if ip:
                        ips.add(str(ip))
        except Exception:
            pass
        return ips

    def set_window_size(self, new_size: int) -> None:
        """Change the sliding window size safely, preserving recent data."""
        new_size = max(1, int(new_size))
        if new_size == self._window_size:
            return
        recent = list(self.packet_data)[-new_size:]
        self.packet_data = deque(recent, maxlen=new_size)
        self._window_size = new_size

    def process_packet(self, packet) -> None:
        """Extract fields from a Scapy packet and append to the window."""
        try:
            if not packet.haslayer(IP):
                return
            ip_layer = packet[IP]
            protocol = getattr(ip_layer, "proto", 0)
            packet_size = int(len(packet)) if hasattr(packet, "__len__") else 0
            if packet.haslayer(TCP):
                sport = int(packet[TCP].sport)
                dport = int(packet[TCP].dport)
            elif packet.haslayer(UDP):
                sport = int(packet[UDP].sport)
                dport = int(packet[UDP].dport)
            else:
                sport = dport = 0
            record = {
                "timestamp": float(getattr(packet, "time", 0.0)),
                "src_ip": str(getattr(ip_layer, "src", "")),
                "dest_ip": str(getattr(ip_layer, "dst", "")),
                "protocol": int(protocol),
                "packet_size": packet_size,
                "sport": sport,
                "dport": dport,
            }
            self.packet_data.append(record)
        except Exception as e:
            print(f"[PacketProcessor] Failed to process packet: {e}")

    def get_dataframe(self) -> pd.DataFrame:
        """Return a DataFrame view of the current sliding window."""
        if not self.packet_data:
            return pd.DataFrame(
                columns=[
                    "timestamp",
                    "src_ip",
                    "dest_ip",
                    "protocol",
                    "packet_size",
                    "sport",
                    "dport",
                ]
            )
        return pd.DataFrame(list(self.packet_data))

    @staticmethod
    def _shannon_entropy_from_series(series: pd.Series) -> float:
        """Compute Shannon entropy (base-2) of value distribution in `series`."""
        if series.empty:
            return 0.0
        counts = series.value_counts(dropna=False).astype(float)
        probs = counts / counts.sum()
        probs = probs[probs > 0.0]
        if probs.empty:
            return 0.0
        return float(-(probs * np.log2(probs)).sum())

    def engineer_features(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """Create numeric features. Returns (features_df, processed_df)."""
        if df is None or df.empty:
            return pd.DataFrame(
                columns=self.FEATURES
            ), df if df is not None else pd.DataFrame()
        df_processed = df.copy()
        df_processed.sort_values("timestamp", inplace=True, kind="mergesort")
        df_processed.reset_index(drop=True, inplace=True)
        df_processed["time_diff"] = df_processed["timestamp"].diff().fillna(0.0)

        df_processed["packet_size_log"] = np.log1p(
            df_processed["packet_size"].astype(float)
        )

        # IANA ephemeral ports default to >= 49152; encode as 1/0
        df_processed["is_ephemeral_sport"] = (
            df_processed["sport"].astype(int) >= 49152
        ).astype(float)

        # Per-source unique destination ports in the last 15 seconds (supports scan/recon detection)
        try:
            current_window = self.get_dataframe()
            if not current_window.empty and "timestamp" in current_window:
                # Use the last packet time in this processed batch as the reference
                ref_ts = float(df_processed["timestamp"].iloc[-1])
                cutoff = ref_ts - 15.0
                recent = current_window[current_window["timestamp"] >= cutoff]
                counts = recent.groupby("src_ip")["dport"].nunique()
                df_processed["unique_dports_15s"] = (
                    df_processed["src_ip"].map(counts).fillna(0.0).astype(float)
                )
            else:
                df_processed["unique_dports_15s"] = 0.0
        except Exception:
            df_processed["unique_dports_15s"] = 0.0

        # Direction flag: outbound (src is this host) = 1.0, inbound otherwise = 0.0
        df_processed["direction"] = (
            df_processed["src_ip"].astype(str).isin(self._local_ips).astype(float)
        )

        features = df_processed.reindex(columns=self.FEATURES).fillna(0.0).astype(float)
        return features, df_processed
