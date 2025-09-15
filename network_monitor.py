# -*- coding: utf-8 -*-
"""
Live network monitor: capture packets, engineer features, and detect anomalies.
"""

from __future__ import annotations

import os
import logging

try:
    import netifaces  # type: ignore
except Exception:  # pragma: no cover
    netifaces = None

try:
    from scapy.all import sniff  # type: ignore
except Exception as e:  # pragma: no cover
    raise RuntimeError("Scapy is required for packet capture: pip install scapy") from e

from packet_processor import PacketProcessor
from anomaly_detector import AnomalyDetector


class NetworkMonitor:
    """Glue code that wires up capture, processing, and the detector."""

    def __init__(self, config) -> None:
        self.config = config
        window_size = self.config.getint("DEFAULT", "DefaultWindowSize", fallback=500)
        self.processor = PacketProcessor(window_size=window_size)

        contamination = self.config.getfloat(
            "IsolationForest", "Contamination", fallback=0.05
        )
        n_estimators = self.config.getint(
            "IsolationForest", "NEstimators", fallback=200
        )
        random_state = self.config.getint("IsolationForest", "RandomState", fallback=42)
        self.detector = AnomalyDetector(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
        )

        self.logger = logging.getLogger("ids.monitor")
        self.logger.setLevel(
            self._parse_log_level(
                self.config.get("Logging", "LogLevel", fallback="INFO")
            )
        )
        self._ensure_handlers()

        self.online_retrain_interval = self.config.getint(
            "Monitoring", "OnlineRetrainInterval", fallback=0
        )
        self._packet_counter = 0

        thr = self.config.get("Monitoring", "AlertThresholds", fallback="-0.10, -0.05")
        parts = [p.strip() for p in thr.split(",") if p.strip()]
        self._thr_high, self._thr_med = (-0.10, -0.05)
        if len(parts) >= 2:
            try:
                self._thr_high, self._thr_med = float(parts[0]), float(parts[1])
            except Exception:
                pass

    @staticmethod
    def _parse_log_level(level_str: str) -> int:
        return getattr(logging, str(level_str).upper(), logging.INFO)

    def _ensure_handlers(self) -> None:
        if not self.logger.handlers:
            ch = logging.StreamHandler()
            ch.setFormatter(
                logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
            )
            self.logger.addHandler(ch)
            if self.config.getboolean("Logging", "EnableFileLogging", fallback=True):
                log_dir = self.config.get("Logging", "LogDirectory", fallback="logs")
                os.makedirs(log_dir, exist_ok=True)
                fh = logging.FileHandler(
                    os.path.join(
                        log_dir,
                        f"{self.config.get('Logging', 'AnomalyLogPrefix', fallback='anomalies')}.log",
                    )
                )
                fh.setFormatter(
                    logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
                )
                self.logger.addHandler(fh)

    def _validate_interface(self, interface: str) -> None:
        if not interface:
            raise ValueError("No network interface specified.")
        if netifaces is None:
            self.logger.warning(
                "netifaces not installed; skipping interface validation."
            )
            return
        interfaces = set(netifaces.interfaces())
        if interface not in interfaces:
            raise ValueError(
                f"Interface '{interface}' not found. Available: {sorted(interfaces)}"
            )

    def capture_and_train(
        self, interface: str, packet_count: int, model_path: str
    ) -> None:
        """Capture `packet_count` packets and train the anomaly detector."""
        self._validate_interface(interface)
        packet_count = int(packet_count)
        if packet_count <= 0:
            raise ValueError("packet_count must be > 0 for training.")
        self.processor.set_window_size(max(self.processor._window_size, packet_count))
        self.logger.info(
            f"Capturing {packet_count} packets on '{interface}' for training..."
        )
        sniff(
            iface=interface,
            prn=self.processor.process_packet,
            count=packet_count,
            store=0,
        )
        df = self.processor.get_dataframe()
        if df.empty:
            raise RuntimeError("No packets captured for training.")
        features, _ = self.processor.engineer_features(df)
        if features.empty:
            raise RuntimeError("Failed to engineer features from captured packets.")
        self.logger.info("Training Isolation Forest...")
        self.detector.train(features)
        self.detector.save_model(model_path)
        self.logger.info(f"Model trained and saved to: {model_path}")

    def start_monitoring(self, interface: str, model_path: str) -> None:
        """Begin live packet sniffing and anomaly detection."""
        self._validate_interface(interface)
        self.detector.load_model(model_path)
        self.logger.info(f"Loaded model: {model_path}")
        self.logger.info(
            f"Starting live monitoring on '{interface}'. Press Ctrl+C to stop."
        )
        try:
            sniff(iface=interface, prn=self._analyze_packet, store=0)
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user.")

    def _analyze_packet(self, packet) -> None:
        """Callback for each captured packet during live monitoring."""
        try:
            self.processor.process_packet(packet)
            window_df = self.processor.get_dataframe()
            if window_df.empty:
                return
            features_df, processed_df = self.processor.engineer_features(window_df)
            if features_df.empty:
                return
            last_feat = features_df.tail(1)
            pred = self.detector.predict(last_feat)[0]
            self._packet_counter += 1
            if pred == "Anomaly":
                # Compute feature-like context for logging (robust even if processor hasn't added them yet)
                last_row = processed_df.tail(1).iloc[0]

                # 1) decision score (more negative => more anomalous)
                try:
                    score = float(self.detector.decision_scores(last_feat)[0])
                except Exception:
                    score = float("nan")

                # 2) ephemeral source port flag (>= 49152)
                try:
                    eph = int(last_row["sport"]) >= 49152
                except Exception:
                    eph = False

                # 3) unique destination ports by source in the last 15 seconds
                try:
                    cutoff = float(last_row["timestamp"]) - 15.0
                    recent = window_df[window_df["timestamp"] >= cutoff]
                    uniq_d = int(
                        recent[recent["src_ip"] == last_row["src_ip"]][
                            "dport"
                        ].nunique()
                    )
                except Exception:
                    uniq_d = 0

                # 4) direction: outbound if src_ip is local; fallback to inbound
                dir_flag = 0  # 0=inbound, 1=outbound
                try:
                    if netifaces is not None:
                        local_ips = set()
                        for iface in netifaces.interfaces():
                            addrs = netifaces.ifaddresses(iface).get(
                                netifaces.AF_INET, []
                            )
                            for a in addrs:
                                ip = a.get("addr")
                                if ip:
                                    local_ips.add(str(ip))
                        dir_flag = 1 if str(last_row["src_ip"]) in local_ips else 0
                except Exception:
                    dir_flag = 0

                # New, feature-aligned log line (keep overall shape similar)
                sev = (
                    self._severity_from_score(score) if score == score else "unknown"
                )  # NaN-safe

                msg = (
                    f"ANOMALY: ts={last_row['timestamp']:.6f} "
                    f"{last_row['src_ip']} -> {last_row['dest_ip']} "
                    f"proto={int(last_row['protocol'])} size={int(last_row['packet_size'])} "
                    f"dport={int(last_row['dport'])} eph_sport={int(eph)} "
                    f"unique_dports_15s={uniq_d} direction={'out' if dir_flag else 'in'} "
                    f"score={score:.3f} severity={sev}"
                )
                self.logger.warning(msg)
                print(
                    "\n--- ANOMALY DETECTED ---\n"
                    + msg
                    + "\n------------------------\n"
                )

            if self.online_retrain_interval > 0 and (
                self._packet_counter % self.online_retrain_interval == 0
            ):
                if len(window_df) >= 50:
                    self.logger.info("Online retraining on current window...")
                    win_features, _ = self.processor.engineer_features(window_df)
                    if not win_features.empty:
                        self.detector.train(win_features)
                        model_path = self.config.get(
                            "DEFAULT", "ModelPath", fallback="models/iforest.joblib"
                        )
                        self.detector.save_model(model_path)
                        self.logger.info("Online retraining complete and model saved.")
        except Exception as e:
            self.logger.error(f"Error during packet analysis: {e}", exc_info=False)

    def _severity_from_score(self, score: float) -> str:
        try:
            if score <= self._thr_high:
                return "high"
            if score <= self._thr_med:
                return "medium"
            return "low"
        except Exception:
            return "unknown"
