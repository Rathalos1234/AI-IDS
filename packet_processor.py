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
    from scapy.all import IP, TCP, UDP  # type: ignore
except Exception:  # pragma: no cover
    IP = TCP = UDP = object

class PacketProcessor:
    """Transforms raw packets into model-ready features."""

    FEATURES = [
        'protocol',
        'packet_size_log',
        'time_diff',
        'packet_rate',
        'sport',
        'dport',
        'ip_entropy',
    ]

    def __init__(self, window_size: int = 500) -> None:
        self._window_size = int(window_size)
        self.packet_data: Deque[Dict] = deque(maxlen=self._window_size)

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
            protocol = getattr(ip_layer, 'proto', 0)
            packet_size = int(len(packet)) if hasattr(packet, '__len__') else 0
            if packet.haslayer(TCP):
                sport = int(packet[TCP].sport)
                dport = int(packet[TCP].dport)
            elif packet.haslayer(UDP):
                sport = int(packet[UDP].sport)
                dport = int(packet[UDP].dport)
            else:
                sport = dport = 0
            record = {
                'timestamp': float(getattr(packet, 'time', 0.0)),
                'src_ip': str(getattr(ip_layer, 'src', '')),
                'dest_ip': str(getattr(ip_layer, 'dst', '')),
                'protocol': int(protocol),
                'packet_size': packet_size,
                'sport': sport,
                'dport': dport,
            }
            self.packet_data.append(record)
        except Exception as e:
            print(f"[PacketProcessor] Failed to process packet: {e}")

    def get_dataframe(self) -> pd.DataFrame:
        """Return a DataFrame view of the current sliding window."""
        if not self.packet_data:
            return pd.DataFrame(columns=['timestamp','src_ip','dest_ip','protocol','packet_size','sport','dport'])
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
            return pd.DataFrame(columns=self.FEATURES), df if df is not None else pd.DataFrame()
        df_processed = df.copy()
        df_processed.sort_values('timestamp', inplace=True, kind='mergesort')
        df_processed.reset_index(drop=True, inplace=True)
        df_processed['time_diff'] = df_processed['timestamp'].diff().fillna(0.0)
        rate = np.where(df_processed['time_diff'] > 0, 1.0 / df_processed['time_diff'], 0.0)
        df_processed['packet_rate'] = rate
        df_processed['packet_size_log'] = np.log1p(df_processed['packet_size'].astype(float))
        try:
            current_window = self.get_dataframe()
            entropy_series = current_window['src_ip'] if 'src_ip' in current_window else df_processed['src_ip']
        except Exception:
            entropy_series = df_processed['src_ip']
        entropy_value = self._shannon_entropy_from_series(entropy_series)
        df_processed['ip_entropy'] = float(entropy_value)
        features = df_processed.reindex(columns=self.FEATURES).fillna(0.0).astype(float)
        return features, df_processed