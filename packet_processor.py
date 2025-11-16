# -*- coding: utf-8 -*-
"""
Packet processing and feature engineering for the AI-Powered IDS.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Mapping, Any, Optional, Iterable, Tuple
import time
import math
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

__all__ = ["PacketProcessor", "IP", "TCP", "UDP", "PacketRecord"]


class PacketWindow:
    __slots__ = ("_buffer", "_capacity", "_start", "_count")

    def __init__(self, capacity: int) -> None:
        self._capacity = max(0, int(capacity))
        self._buffer: list[Any] = [None] * self._capacity
        self._start = 0
        self._count = 0

    @property
    def maxlen(self) -> int:
        return self._capacity

    def __len__(self) -> int:
        return self._count

    def append(self, item: Any) -> None:
        if self._capacity == 0:
            return
        if self._count < self._capacity:
            idx = (self._start + self._count) % self._capacity
            self._buffer[idx] = item
            self._count += 1
        else:
            self._buffer[self._start] = item
            self._start = (self._start + 1) % self._capacity

    def popleft(self) -> Any:
        if self._count == 0:
            raise IndexError("pop from an empty PacketWindow")
        item = self._buffer[self._start]
        self._start = (self._start + 1) % self._capacity
        self._count -= 1
        return item

    def clear(self) -> None:
        self._start = 0
        self._count = 0

    def extend(self, records: Iterable[Any]) -> None:
        for record in records:
            self.append(record)

    def __iter__(self):
        for i in range(self._count):
            yield self._buffer[(self._start + i) % self._capacity]

    def to_list(self) -> list[Any]:
        return list(self)


@dataclass(slots=True)
class PacketRecord:
    timestamp: float
    src_ip: str
    dest_ip: str
    protocol: int
    packet_size: int
    sport: int
    dport: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dest_ip": self.dest_ip,
            "protocol": self.protocol,
            "packet_size": self.packet_size,
            "sport": self.sport,
            "dport": self.dport,
        }


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
        self.packet_data: PacketWindow = PacketWindow(self._window_size)
        self._record_pool: list[PacketRecord] = [
            PacketRecord(0.0, "", "", 0, 0, 0, 0) for _ in range(self._window_size)
        ]
        self._last_timestamp: Optional[float] = None
        self._active_ports: Dict[str, Dict[int, float]] = {}
        self._feature_buffer: Dict[str, float] = {name: 0.0 for name in self.FEATURES}

    @property
    def window_size(self) -> int:
        """Return the current sliding window size used for packet retention."""
        return self._window_size

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
        current = self.packet_data.to_list()
        recent = current[-new_size:]
        trimmed = current[:-new_size]
        self.packet_data = PacketWindow(new_size)
        self.packet_data.extend(recent)
        for entry in trimmed:
            if isinstance(entry, PacketRecord):
                self._record_pool.append(entry)
        pool_target = max(0, new_size - len(self.packet_data))
        if len(self._record_pool) < pool_target:
            self._record_pool.extend(
                PacketRecord(0.0, "", "", 0, 0, 0, 0)
                for _ in range(pool_target - len(self._record_pool))
            )
        elif len(self._record_pool) > pool_target:
            del self._record_pool[pool_target:]
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
            record = PacketRecord(
                timestamp=float(getattr(packet, "time", 0.0)),
                src_ip=str(getattr(ip_layer, "src", "")),
                dest_ip=str(getattr(ip_layer, "dst", "")),
                protocol=int(protocol),
                packet_size=packet_size,
                sport=sport,
                dport=dport,
            )
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
        return self._records_to_frame(self.packet_data)

    @staticmethod
    def _records_to_frame(records: Iterable[Any]) -> pd.DataFrame:
        converted = []
        for entry in records:
            if isinstance(entry, PacketRecord):
                converted.append(entry.as_dict())
            else:
                converted.append(dict(entry))
        return pd.DataFrame(converted)

    def extract_features(self, packet: Mapping[str, Any]) -> Dict[str, float]:
        """Return engineered features for a dictionary like packet payload."""

        if packet is None:
            raise ValueError("packet is required")

        try:
            timestamp = packet["timestamp"]
        except KeyError:
            timestamp = packet.get("ts", time.time())
        timestamp = float(timestamp)

        try:
            src_ip = packet["src_ip"]
        except KeyError:
            src_ip = packet.get("source") or packet.get("ip", "")
        src_ip = str(src_ip)

        try:
            dest_ip = packet["dest_ip"]
        except KeyError:
            dest_ip = packet.get("dst_ip") or packet.get("destination", "")
        dest_ip = str(dest_ip)

        proto = packet.get("protocol")
        if proto is None:
            proto = packet.get("proto", 0)
        if isinstance(proto, str):
            mapping = {"tcp": 6, "udp": 17, "icmp": 1}
            proto = mapping.get(proto.lower(), 0)
        protocol = int(proto)

        packet_size = packet.get("packet_size")
        if packet_size is None:
            packet_size = packet.get("length")
        if packet_size is None:
            packet_size = packet.get("size", 0)
        packet_size = int(packet_size)

        sport = packet.get("sport")
        if sport is None:
            sport = packet.get("src_port")
        if sport is None:
            sport = packet.get("source_port", 0)
        sport = int(sport)

        dport = packet.get("dport")
        if dport is None:
            dport = packet.get("dst_port")
        if dport is None:
            dport = packet.get("destination_port", 0)
        dport = int(dport)

        maxlen = self.packet_data.maxlen or 0
        if self._record_pool:
            record = self._record_pool.pop()
        elif maxlen and len(self.packet_data) == maxlen:
            reusable = self.packet_data.popleft()
            record = (
                reusable
                if isinstance(reusable, PacketRecord)
                else PacketRecord(0.0, "", "", 0, 0, 0, 0)
            )
        else:
            record = PacketRecord(0.0, "", "", 0, 0, 0, 0)

        record.timestamp = timestamp
        record.src_ip = src_ip
        record.dest_ip = dest_ip
        record.protocol = protocol
        record.packet_size = packet_size
        record.sport = sport
        record.dport = dport

        self.packet_data.append(record)

        return self._compute_incremental_features(record)

    def _compute_incremental_features(self, record: PacketRecord) -> Dict[str, float]:
        """Fast path feature computation for single packets."""

        timestamp = float(record.timestamp)
        protocol = float(record.protocol)
        packet_size = float(record.packet_size)
        sport = int(record.sport)
        dport = int(record.dport)
        src_ip = str(record.src_ip)

        last_timestamp = self._last_timestamp
        if last_timestamp is None:
            time_diff = 0.0
        else:
            time_diff = timestamp - last_timestamp
            if time_diff < 0.0:
                time_diff = 0.0
        self._last_timestamp = timestamp

        packet_size_log = math.log1p(packet_size) if packet_size > 0 else 0.0
        is_ephemeral = 1.0 if sport >= 49152 else 0.0
        unique_dports = float(self._update_unique_dports(timestamp, src_ip, dport))
        direction = 1.0 if self._local_ips and src_ip in self._local_ips else 0.0

        return {
            "protocol": protocol,
            "packet_size_log": packet_size_log,
            "time_diff": time_diff,
            "dport": float(dport),
            "is_ephemeral_sport": is_ephemeral,
            "unique_dports_15s": unique_dports,
            "direction": direction,
        }

    def _update_unique_dports(self, timestamp: float, src_ip: str, dport: int) -> int:
        """Track unique destination ports seen per source in the trailing 15s window."""

        cutoff = timestamp - 15.0

        ports = self._active_ports.setdefault(src_ip, {})
        ports[dport] = timestamp

        if ports:
            stale = [port for port, seen_at in ports.items() if seen_at < cutoff]
            for port in stale:
                ports.pop(port, None)

        if not ports:
            self._active_ports.pop(src_ip, None)
            return 0

        return len(ports)

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
        if df.index.is_monotonic_increasing and df["timestamp"].is_monotonic_increasing:
            df_processed = df.reset_index(drop=True)
        else:
            df_processed = df.sort_values(
                "timestamp", kind="mergesort", ignore_index=True
            )

        ts = df_processed["timestamp"].to_numpy(dtype=np.float64, copy=False)
        time_diff = np.empty_like(ts, dtype=np.float64)
        if len(ts):
            time_diff[0] = 0.0
            if len(ts) > 1:
                np.subtract(ts[1:], ts[:-1], out=time_diff[1:])
        df_processed["time_diff"] = (
            time_diff if len(ts) else np.array([], dtype=np.float64)
        )

        sizes = df_processed["packet_size"].to_numpy(dtype=np.float64, copy=False)
        df_processed["packet_size_log"] = np.log1p(sizes)

        # IANA ephemeral ports default to >= 49152; encode as 1/0
        sports = df_processed["sport"].to_numpy(dtype=np.int64, copy=False)
        df_processed["is_ephemeral_sport"] = (sports >= 49152).astype(np.float64)

        # Per-source unique destination ports in the last 15 seconds (supports scan/recon detection)
        try:
            if self.packet_data:
                current_window = self._records_to_frame(self.packet_data)
                if "timestamp" in current_window:
                    # Use the last packet time in this processed batch as the reference
                    ref_ts = float(ts[-1])
                    cutoff = ref_ts - 15.0
                    recent = current_window[current_window["timestamp"] >= cutoff]
                    counts = recent.groupby("src_ip")["dport"].nunique()
                    df_processed["unique_dports_15s"] = (
                        df_processed["src_ip"].map(counts).fillna(0.0).astype(float)
                    )
                else:
                    df_processed["unique_dports_15s"] = 0.0
            else:
                df_processed["unique_dports_15s"] = 0.0
        except Exception:
            df_processed["unique_dports_15s"] = 0.0

        # Direction flag: outbound (src is this host) = 1.0, inbound otherwise = 0.0
        if self._local_ips:
            src_ips = df_processed["src_ip"].astype(str).to_numpy(copy=False)
            df_processed["direction"] = np.isin(src_ips, list(self._local_ips)).astype(
                np.float64
            )
        else:
            df_processed["direction"] = 0.0

        feature_view = df_processed.loc[:, self.FEATURES].to_numpy(
            dtype=np.float64, copy=False
        )
        if np.isnan(feature_view).any():
            feature_view = np.nan_to_num(feature_view, nan=0.0, posinf=0.0, neginf=0.0)
        features = pd.DataFrame(feature_view, columns=self.FEATURES)
        return features, df_processed
