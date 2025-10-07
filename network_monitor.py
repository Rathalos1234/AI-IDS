# -*- coding: utf-8 -*-
"""
Live network monitor: capture packets, engineer features, and detect anomalies.
"""

from __future__ import annotations

import os
import logging
import ipaddress
import uuid
from datetime import datetime
import webdb
import ipaddress

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

from typing import Any, Dict, List, cast

from signature_engine import default_engine


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

        # Rolling features capture (for quick repros/ad-hoc retraining)
        self.save_rolling = self.config.getboolean(
            "Training", "SaveRollingParquet", fallback=True
        )
        self.rolling_path = self.config.get(
            "Training", "RollingParquetPath", fallback="data/rolling.parquet"
        )

        thr = self.config.get("Monitoring", "AlertThresholds", fallback="-0.10, -0.05")
        parts = [p.strip() for p in thr.split(",") if p.strip()]
        self._thr_high, self._thr_med = (-0.10, -0.05)
        if len(parts) >= 2:
            try:
                self._thr_high, self._thr_med = float(parts[0]), float(parts[1])
            except Exception:
                pass

        # Signature engine toggle
        self.enable_sigs = self.config.getboolean("Signatures", "Enable", fallback=True)
        self.sig_engine = default_engine() if self.enable_sigs else None

        
        # Ensure the Web UI database exists for alert inserts
        try:
            webdb.init()
        except Exception:
            # Don't crash monitoring if DB init fails
            self.logger = logging.getLogger("ids.monitor")
            self.logger.debug("webdb.init() failed", exc_info=True)

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
        # Startup banner with model + thresholds details
        try:
            info = self.detector.bundle_metadata()
            params = info.get("params", {}) or {}

            info = cast(Dict[str, Any], self.detector.bundle_metadata())
            params = cast(Dict[str, Any], info.get("params", {}) or {})

            self.logger.info(
                "Model info: version=%s trained_at=%s features=%d checksum=%s",
                info.get("version", ""),
                info.get("trained_at", ""),
                info.get("feature_count", 0),
                str(info.get("feature_checksum", ""))[:12] + "…",
            )
            self.logger.info(
                "IF params: contamination=%s n_estimators=%s random_state=%s",
                params.get("contamination"),
                params.get("n_estimators"),
                params.get("random_state"),
            )

            fnames = cast(List[str], info.get("feature_names", []) or [])

            if fnames:
                self.logger.info("Feature order: %s", ", ".join(map(str, fnames)))
        except Exception:
            # Non-fatal; continue monitoring even if banner fails
            pass
        self.logger.info(
            "Alert thresholds: high<=%.3f  medium<=%.3f | online_retrain_interval=%d",
            self._thr_high,
            self._thr_med,
            self.online_retrain_interval,
        )
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

            # Persist engineered rows to a rolling Parquet file (best effort)
            if self.save_rolling and not processed_df.empty:
                os.makedirs(os.path.dirname(self.rolling_path) or ".", exist_ok=True)
                try:
                    # Prefer append (supported by some pandas/pyarrow combos)
                    processed_df.to_parquet(
                        self.rolling_path,
                        engine="pyarrow",
                        append=True,  # type: ignore[arg-type]
                    )
                except Exception:
                    # Fallback: overwrite if append isn't supported
                    try:
                        processed_df.to_parquet(self.rolling_path, engine="pyarrow")
                    except Exception:
                        pass

            # --- NEW: record devices seen on the network (private IPs only) ---
            try:
                last_row_dev = processed_df.tail(1).iloc[0]
                sip = str(last_row_dev.get("src_ip"))
                dip = str(last_row_dev.get("dest_ip"))
                if sip and ipaddress.ip_address(sip).is_private:
                    webdb.record_device(sip)
                if dip and ipaddress.ip_address(dip).is_private:
                    webdb.record_device(dip)
            except Exception:
                self.logger.debug("record_device failed", exc_info=True)

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
                sev = self._severity_from_score(score) if score == score else "unknown"
                msg = (
                    f"ANOMALY: ts={last_row['timestamp']:.6f} "
                    f"{last_row['src_ip']} -> {last_row['dest_ip']} "
                    f"proto={int(last_row['protocol'])} size={int(last_row['packet_size'])} "
                    f"dport={int(last_row['dport'])} eph_sport={int(eph)} "
                    f"unique_dports_15s={uniq_d} direction={'out' if dir_flag else 'in'} "
                    f"score={score:.3f} severity={sev}"
                )

                
                self._emit(msg, sev)  # severity-aware logger

                # NEW: sink anomaly to WebDB so the GUI can see it
                try:
                    webdb.insert_alert({
                        "id": str(uuid.uuid4()),
                        "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                        "src_ip": str(last_row["src_ip"]),
                        "label": f"{last_row['dest_ip']}:{int(last_row['dport'])} score={score:.3f}",
                        "severity": str(sev).upper(),   # LOW/MEDIUM/HIGH
                        "kind": "ANOMALY",
                    })
                except Exception:
                    self.logger.debug("webdb.insert_alert failed (anomaly)", exc_info=True)

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

            # NEW: signature evaluation (best after we have processed_df/window_df)
            if self.sig_engine is not None and not processed_df.empty:
                last_row_dict = processed_df.tail(1).iloc[0].to_dict()
                for hit in self.sig_engine.evaluate(last_row_dict, window_df):
                    s_msg = (
                        f"SIGNATURE: {hit.name} severity={hit.severity} | "
                        f"{last_row_dict.get('src_ip')} -> {last_row_dict.get('dest_ip')} "
                        f'dport={int(last_row_dict.get("dport", 0))} desc="{hit.description}"'
                    )
                    self._emit(s_msg, hit.severity)


                    # NEW: sink signature hit to WebDB (also visible in Log History)
                    try:
                        webdb.insert_alert({
                            "id": str(uuid.uuid4()),
                            "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
                            "src_ip": str(last_row_dict.get("src_ip")),
                            "label": f"{hit.name} {last_row_dict.get('dest_ip')}:{int(last_row_dict.get('dport',0))}",
                            "severity": str(hit.severity or "").upper(),
                            "kind": "SIGNATURE",
                        })
                    except Exception:
                        self.logger.debug("webdb.insert_alert failed (signature)", exc_info=True)

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

    # NEW: centralized severity emitter
    def _emit(self, msg: str, severity: str) -> None:
        sev = (severity or "").lower()
        if sev == "high":
            self.logger.error(msg)
        elif sev == "medium":
            self.logger.warning(msg)
        else:
            self.logger.info(msg)
