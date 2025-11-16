# -*- coding: utf-8 -*-
"""
Live network monitor: capture packets, engineer features, and detect anomalies.
"""

from __future__ import annotations
import os
import logging
import math
import random
import threading
import time
import uuid
from datetime import datetime, timezone
import webdb
from typing import Any, Dict, List, Set, cast, Optional
import ipaddress
import pandas as pd
from anomaly_detector import AnomalyDetector
from firewall import capabilities as firewall_capabilities
from firewall import ensure_block as firewall_ensure_block
from packet_processor import IP, TCP, UDP, PacketProcessor
from signature_engine import default_engine


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso_utc(dt: datetime) -> str:
    return (
        dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )


try:
    import netifaces  # type: ignore
except Exception:  # pragma: no cover
    netifaces = None

try:
    from scapy.all import sniff  # type: ignore
except Exception as e:  # pragma: no cover
    raise RuntimeError("Scapy is required for packet capture: pip install scapy") from e


class _FakeLayer:
    def __init__(self, **attrs: Any) -> None:
        self.__dict__.update(attrs)

    def __getattr__(self, item: str) -> Any:
        return self.__dict__.get(item)


class _SyntheticPacket:
    """Tiny Scapy-like packet used when generating fake traffic."""

    __slots__ = ("time", "_layers", "_len")

    def __init__(
        self,
        *,
        timestamp: float,
        length: int,
        src: str,
        dest: str,
        proto: int,
        sport: int,
        dport: int,
    ) -> None:
        self.time = timestamp
        self._len = length
        self._layers: dict[Any, _FakeLayer] = {
            IP: _FakeLayer(src=src, dst=dest, proto=proto),
        }
        transport_cls = TCP if proto == 6 else UDP
        self._layers[transport_cls] = _FakeLayer(sport=sport, dport=dport)

    def haslayer(self, layer: Any) -> bool:
        return layer in self._layers

    def __getitem__(self, layer: Any) -> _FakeLayer:
        return self._layers[layer]

    def __len__(self) -> int:
        return self._len


def _as_int(value: Any, default: int = 0) -> int:
    try:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return default if math.isnan(value) else int(value)
        return int(float(value))
    except Exception:
        return default


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        if isinstance(value, float):
            return value
        return float(value)
    except Exception:
        return default


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

        # Runtime firewall + simulation knobs
        self.firewall_capabilities = firewall_capabilities()
        self.firewall_runtime_enabled = False
        self._runtime_blocked: Set[str] = set()
        self._simulate_mode = False
        self._simulate_thread: Optional[threading.Thread] = None

        # Online retraining coordination
        self._retrain_lock = threading.Lock()
        self._retrain_thread: Optional[threading.Thread] = None
        self._pending_retrain: Optional[pd.DataFrame] = None

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

    def capture_and_train_until_interrupt(
        self, interface: str, model_path: str, *, min_packets: int = 100
    ) -> None:
        """
        Capture packets indefinitely and, on Ctrl+C, train the model on what was captured.
        A larger window is used so the processor retains more rows before training.
        """
        self._validate_interface(interface)
        # Allow configuring a larger rolling window just for this mode (default: 100k)
        until_window = self.config.getint(
            "Training", "UntilCtrlCWindow", fallback=100_000
        )
        try:
            self.processor.set_window_size(
                max(self.processor._window_size, int(until_window))
            )
        except Exception:
            # Best-effort; continue with existing window if resizing fails
            pass

        self.logger.info(
            f"Capturing on '{interface}' for training until Ctrl+C... "
            "(will train on collected traffic at interrupt)"
        )
        try:
            sniff(iface=interface, prn=self.processor.process_packet, store=0)
        except KeyboardInterrupt:
            self.logger.info("Stopping capture and training the model...")

        df = self.processor.get_dataframe()
        n_rows = int(getattr(df, "__len__", lambda: 0)())
        if n_rows == 0 or df.empty:
            raise RuntimeError("No packets captured for training.")
        if n_rows < max(1, int(min_packets)):
            self.logger.warning(
                "Only %d packets captured (< min %d). Training anyway.",
                n_rows,
                int(min_packets),
            )

        features, _ = self.processor.engineer_features(df)
        if features.empty:
            raise RuntimeError("Failed to engineer features from captured packets.")

        self.logger.info("Training Isolation Forest on %d packets...", n_rows)
        self.detector.train(features)
        self.detector.save_model(model_path)
        self.logger.info("Model trained and saved to: %s", model_path)

    def start_monitoring(
        self,
        interface: str,
        model_path: str,
        *,
        firewall_blocking: bool = False,
        simulate: bool = False,
    ) -> None:
        """Begin live packet sniffing and anomaly detection."""
        if not simulate:
            self._validate_interface(interface)
        self.detector.load_model(model_path)
        self.logger.info(f"Loaded model: {model_path}")
        self.firewall_runtime_enabled = bool(firewall_blocking) and bool(
            self.firewall_capabilities.get("supported")
        )
        self._simulate_mode = bool(simulate)
        if firewall_blocking and not self.firewall_runtime_enabled:
            self.logger.warning(
                "Firewall blocking requested but unavailable (capabilities=%s)",
                self.firewall_capabilities,
            )
        if self.firewall_runtime_enabled:
            self.logger.info("Runtime firewall auto-blocking enabled")
            self._sync_firewall_blocks_from_db()
        if self._simulate_mode:
            self.logger.info("Simulated traffic enabled — generating synthetic flows")
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
        if self._simulate_mode:
            self.logger.info(
                "Starting synthetic monitoring loop (interface hint: %s)", interface
            )
            if self.online_retrain_interval <= 0:
                self.logger.info(
                    "Simulation loop skipped (online retrain interval disabled)."
                )
                return
            try:
                self._simulate_loop()
            except KeyboardInterrupt:
                self.logger.info("Simulation stopped by user.")
            return
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

                # --- Works for all valid IPs
                seen_ips = []
                for candidate in (sip, dip):
                    if not candidate:
                        continue
                    try:
                        ipaddress.ip_address(candidate)
                    except ValueError:
                        continue
                    seen_ips.append(candidate)
                for candidate in dict.fromkeys(seen_ips):
                    webdb.record_device(candidate)

            # --- Works for private IPs only
            #                if sip and ipaddress.ip_address(sip).is_private:
            #                    webdb.record_device(sip)
            #                if dip and ipaddress.ip_address(dip).is_private:
            #                    webdb.record_device(dip)

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
                    eph = _as_int(last_row.get("sport")) >= 49152
                except Exception:
                    eph = False

                # 3) unique destination ports by source in the last 15 seconds
                try:
                    cutoff = _as_float(last_row.get("timestamp")) - 15.0
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
                ts_val = _as_float(last_row.get("timestamp"))
                src_ip = str(last_row.get("src_ip", ""))
                dest_ip = str(last_row.get("dest_ip", ""))
                msg = (
                    f"ANOMALY: ts={ts_val:.6f} "
                    f"{src_ip} -> {dest_ip} "
                    f"proto={_as_int(last_row.get('protocol'))} "
                    f"size={_as_int(last_row.get('packet_size'))} "
                    f"dport={_as_int(last_row.get('dport'))} eph_sport={int(eph)} "
                    f"unique_dports_15s={uniq_d} direction={'out' if dir_flag else 'in'} "
                    f"score={score:.3f} severity={sev}"
                )

                self._emit(msg, sev)  # severity-aware logger

                if self.firewall_runtime_enabled and (sev or "").lower() == "high":
                    self._maybe_firewall_block(
                        str(last_row.get("src_ip", "")),
                        sev,
                        f"{dest_ip}:{_as_int(last_row.get('dport'))}",
                    )

                # NEW: sink anomaly to WebDB so the GUI can see it
                try:
                    webdb.insert_alert(
                        {
                            "id": str(uuid.uuid4()),
                            "ts": _iso_utc(_utcnow()),
                            "src_ip": str(last_row["src_ip"]),
                            "label": (
                                f"{dest_ip}:{_as_int(last_row.get('dport'))} "
                                f"score={score:.3f}"
                            ),
                            "severity": str(sev).upper(),  # LOW/MEDIUM/HIGH
                            "kind": "ANOMALY",
                        }
                    )
                except Exception:
                    self.logger.debug(
                        "webdb.insert_alert failed (anomaly)", exc_info=True
                    )

                print(
                    "\n--- ANOMALY DETECTED ---\n"
                    + msg
                    + "\n------------------------\n"
                )

            if self.online_retrain_interval > 0 and (
                self._packet_counter % self.online_retrain_interval == 0
            ):
                if len(window_df) >= 50:
                    training_features = features_df.copy(deep=True)
                    if not training_features.empty:
                        self.logger.info("Online retraining on current window...")
                        self._schedule_async_retrain(training_features)

            # NEW: signature evaluation (best after we have processed_df/window_df)
            if self.sig_engine is not None and not processed_df.empty:
                last_row_dict = processed_df.tail(1).iloc[0].to_dict()
                for hit in self.sig_engine.evaluate(last_row_dict, window_df):
                    s_msg = (
                        f"SIGNATURE: {hit.name} severity={hit.severity} | "
                        f"{last_row_dict.get('src_ip')} -> {last_row_dict.get('dest_ip')} "
                        f'dport={_as_int(last_row_dict.get("dport"))} desc="{hit.description}"'
                    )
                    self._emit(s_msg, hit.severity)

                    # NEW: sink signature hit to WebDB (also visible in Log History)
                    try:
                        webdb.insert_alert(
                            {
                                "id": str(uuid.uuid4()),
                                "ts": _iso_utc(_utcnow()),
                                "src_ip": str(last_row_dict.get("src_ip")),
                                "label": (
                                    f"{hit.name} {last_row_dict.get('dest_ip')}:"
                                    f"{_as_int(last_row_dict.get('dport'))}"
                                ),
                                "severity": str(hit.severity or "").upper(),
                                "kind": "SIGNATURE",
                            }
                        )
                    except Exception:
                        self.logger.debug(
                            "webdb.insert_alert failed (signature)", exc_info=True
                        )

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

    def _maybe_firewall_block(self, ip: str, severity: str, detail: str) -> None:
        ip = (ip or "").strip()
        if not ip or ip in self._runtime_blocked:
            return
        try:
            if ip in getattr(self.processor, "_local_ips", set()):
                return
        except Exception:
            pass
        try:
            parsed = ipaddress.ip_address(ip)
            if parsed.is_loopback:
                return
        except Exception:
            return
        # Skip trusted hosts when possible
        if hasattr(webdb, "is_trusted"):
            try:
                if webdb.is_trusted(ip):
                    self.logger.info("Skip auto-block for trusted IP %s", ip)
                    return
            except Exception:
                pass
        ok, err = firewall_ensure_block(ip, f"auto-{severity}")
        if ok:
            self._runtime_blocked.add(ip)
            self.logger.warning("Auto-blocked %s via firewall (%s)", ip, detail)
            try:
                webdb.delete_action_by_ip(ip, "unblock")
                webdb.delete_action_by_ip(ip, "block")
                webdb.insert_block(
                    {
                        "id": str(uuid.uuid4()),
                        "ts": _iso_utc(_utcnow()),
                        "ip": ip,
                        "action": "block",
                        "reason": f"auto-{severity}",
                        "expires_at": "",
                    }
                )
            except Exception:
                self.logger.debug("auto block persistence failed", exc_info=True)
        elif err:
            self.logger.error("Firewall auto-block failed for %s: %s", ip, err)

    def _schedule_async_retrain(
        self, features: pd.DataFrame
    ) -> Optional[threading.Thread]:
        """Kick off an online retrain without blocking packet processing."""

        snapshot = features.copy(deep=True)
        with self._retrain_lock:
            if self._retrain_thread and self._retrain_thread.is_alive():
                self._pending_retrain = snapshot
                return None

            self._pending_retrain = None
            thread = threading.Thread(
                target=self._run_retrain, args=(snapshot,), daemon=True
            )
            self._retrain_thread = thread
            thread.start()
            return thread

    def _run_retrain(self, features: pd.DataFrame) -> None:
        next_features: Optional[pd.DataFrame] = None
        try:
            self.detector.train(features)
            model_path = self.config.get(
                "DEFAULT", "ModelPath", fallback="models/iforest.joblib"
            )
            self.detector.save_model(model_path)
            self.logger.info("Online retraining complete and model saved.")
        except Exception:
            self.logger.exception("Online retraining failed")
        finally:
            with self._retrain_lock:
                self._retrain_thread = None
                if self._pending_retrain is not None:
                    next_features = self._pending_retrain
                    self._pending_retrain = None

        if next_features is not None:
            self._schedule_async_retrain(next_features)

    def _sync_firewall_blocks_from_db(self) -> None:
        """Ensure persisted block entries are enforced when monitoring starts."""

        if not self.firewall_runtime_enabled:
            return

        try:
            rows = webdb.list_blocks(limit=5_000)
        except Exception:
            self.logger.warning(
                "Unable to read persisted firewall blocks during startup", exc_info=True
            )
            return

        applied = 0
        for entry in rows:
            if (entry.get("action") or "").lower() != "block":
                continue
            ip = (entry.get("ip") or "").strip()
            if not ip or ip in self._runtime_blocked:
                continue
            reason = (entry.get("reason") or "startup-sync").strip() or "startup-sync"
            ok, err = firewall_ensure_block(ip, reason)
            if ok:
                self._runtime_blocked.add(ip)
                applied += 1
            else:
                self.logger.warning(
                    "Failed to sync firewall block for %s: %s", ip, err or "unknown"
                )

        if applied:
            self.logger.info("Applied %d firewall blocks from persisted state", applied)

    def _simulate_loop(self) -> None:
        local_ips = list(getattr(self.processor, "_local_ips", [])) or ["192.168.1.10"]
        remote_pool = [
            "45.83.12.5",
            "91.210.44.19",
            "203.0.113.45",
            "198.51.100.88",
            "176.31.72.14",
        ]
        service_ports = [22, 53, 80, 123, 389, 443, 502, 8080, 8443]
        rng = random.Random()
        # We detect test here which is probably not great practice but its just to limit the ammount of packets so it should be fine.
        max_iterations: Optional[int] = (
            500 if os.getenv("PYTEST_CURRENT_TEST") else None
        )

        while True:
            now = time.time()
            # Occasionally emit a bursty inbound scan to trigger anomalies
            if rng.random() < 0.18:
                attacker = rng.choice(remote_pool)
                victim = rng.choice(local_ips)
                for dport in rng.sample(range(20, 1050), rng.randint(6, 10)):
                    pkt = _SyntheticPacket(
                        timestamp=now + rng.random() * 0.05,
                        length=rng.randint(60, 900),
                        src=attacker,
                        dest=victim,
                        proto=6,
                        sport=rng.randint(1024, 65535),
                        dport=dport,
                    )
                    self._analyze_packet(pkt)
                    time.sleep(rng.uniform(0.03, 0.07))
                continue

            outbound = rng.random() < 0.55
            if outbound:
                src = rng.choice(local_ips)
                dest = rng.choice(remote_pool)
            else:
                src = rng.choice(remote_pool)
                dest = rng.choice(local_ips)

            proto = 6 if rng.random() < 0.7 else 17
            dport = rng.choice(service_ports + [rng.randint(1024, 65535)])
            sport = rng.randint(49152, 65535)
            pkt = _SyntheticPacket(
                timestamp=now,
                length=rng.randint(70, 1400),
                src=src,
                dest=dest,
                proto=proto,
                sport=sport,
                dport=dport,
            )
            self._analyze_packet(pkt)
            time.sleep(rng.uniform(0.05, 0.25))

            if max_iterations is not None:
                max_iterations -= 1
                if max_iterations <= 0:
                    break
