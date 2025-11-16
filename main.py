# -*- coding: utf-8 -*-
"""CLI entrypoint for the AI-Powered IDS."""

from __future__ import annotations

import argparse
import configparser
import json
import os
import shutil
import socket
import sys
import threading
from datetime import datetime
from network_monitor import NetworkMonitor
from anomaly_detector import AnomalyDetector
from config_validation import validate_config
from typing import Any, Dict, List, cast
import webdb

_API_THREAD: threading.Thread | None = None


def _is_port_listening(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        try:
            sock.connect((host, port))
            return True
        except OSError:
            return False


def _start_api_server_in_background() -> None:
    global _API_THREAD
    if os.environ.get("DISABLE_EMBEDDED_API", "0") == "1":
        return
    host = os.environ.get("API_HOST", "127.0.0.1")
    port = int(os.environ.get("API_PORT", "5000"))
    if _API_THREAD and _API_THREAD.is_alive():
        return
    if _is_port_listening(host, port):
        return
    try:
        from api import app as flask_app  # noqa: WPS433 (import within function)
    except Exception as exc:  # pragma: no cover - best-effort startup helper
        print(f"[WARN] Unable to start API server automatically: {exc}")
        return

    def _run() -> None:
        flask_app.run(host, port, debug=False, use_reloader=False)

    _API_THREAD = threading.Thread(target=_run, daemon=True, name="api-server")
    _API_THREAD.start()
    print(f"[INFO] Embedded API server listening on http://{host}:{port}")


def _load_config(config_path: str) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    read = cfg.read(config_path)
    if not read:
        print(
            f"[WARN] Could not read config file at '{config_path}'. Using defaults where possible."
        )
    # NEW: fail fast on bad configs
    validate_config(cfg)
    return cfg


def build_arg_parser(cfg: configparser.ConfigParser) -> argparse.ArgumentParser:
    default_iface = cfg.get("DEFAULT", "DefaultInterface", fallback="eth0")
    default_count = cfg.getint("DEFAULT", "DefaultPacketCount", fallback=1000)
    default_model = cfg.get("DEFAULT", "ModelPath", fallback="models/iforest.joblib")
    p = argparse.ArgumentParser(
        description="AI-Powered IDS: Train or monitor network traffic using Isolation Forest."
    )
    sub = p.add_subparsers(dest="mode", required=True, help="Sub-commands")
    pt = sub.add_parser("train", help="Capture packets and train the model.")
    pt.add_argument(
        "--interface", "-i", default=default_iface, help="Network interface to use."
    )
    pt.add_argument(
        "--count",
        "-c",
        type=int,
        default=default_count,
        help="Number of packets to capture for training.",
    )
    pt.add_argument(
        "--until-ctrl-c",
        "--until",
        dest="until_ctrl_c",
        action="store_true",
        help="Capture indefinitely; stop with Ctrl+C, then train on collected traffic.",
    )
    pt.add_argument(
        "--min-packets",
        type=int,
        default=100,
        help="Soft minimum packets before training (only used with --until-ctrl-c).",
    )
    pt.add_argument(
        "--model",
        "-m",
        default=default_model,
        help="Path to save the trained model (joblib).",
    )
    pm = sub.add_parser("monitor", help="Start live monitoring with a trained model.")
    pm.add_argument(
        "--interface", "-i", default=default_iface, help="Network interface to use."
    )
    pm.add_argument(
        "--model",
        "-m",
        default=default_model,
        help="Path to the trained model (joblib).",
    )
    fw_default = cfg.getboolean("Monitoring", "FirewallBlocking", fallback=False)
    pm.add_argument(
        "--firewall-blocking",
        dest="firewall_blocking",
        action="store_true",
        help="Enable runtime firewall blocking for high-severity anomalies.",
    )
    pm.add_argument(
        "--no-firewall-blocking",
        dest="firewall_blocking",
        action="store_false",
        help="Disable runtime firewall blocking (default).",
    )
    pm.set_defaults(firewall_blocking=fw_default)

    sim_default = cfg.getboolean("Monitoring", "SimulateTraffic", fallback=False)
    pm.add_argument(
        "--simulate-traffic",
        dest="simulate_traffic",
        action="store_true",
        help="Generate synthetic packets instead of sniffing a real interface.",
    )
    pm.add_argument(
        "--no-simulate-traffic",
        dest="simulate_traffic",
        action="store_false",
        help="Capture live packets from the selected interface.",
    )
    pm.set_defaults(simulate_traffic=sim_default)
    pv = sub.add_parser("verify-model", help="Inspect a trained model bundle.")
    pv.add_argument(
        "--model",
        "-m",
        default=default_model,
        help="Path to the trained model (joblib).",
    )

    _ = sub.add_parser("config-validate", help="Validate configuration and exit.")

    # --- tiny ops helpers ---
    pbd = sub.add_parser(
        "backup-db", help="Create a timestamped copy of the web database"
    )
    pbd.add_argument("-o", "--outdir", default="backups", help="destination directory")

    pr = sub.add_parser(
        "retention-run",
        help="Prune old alerts/blocks per config.ini (or CLI overrides)",
    )
    pr.add_argument(
        "--alerts-days", type=int, default=None, help="override Retention.AlertsDays"
    )
    pr.add_argument(
        "--blocks-days", type=int, default=None, help="override Retention.BlocksDays"
    )

    return p


def cmd_backup_db(args) -> int:
    """Write a timestamped copy of the SQLite DB into args.outdir."""
    try:
        db_path = str(webdb.DB)
    except Exception as e:
        print(f"[backup-db] cannot locate DB: {e}", file=sys.stderr)
        return 1
    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    dest = os.path.join(outdir, f"ids_web_{ts}.sqlite")
    shutil.copyfile(db_path, dest)
    print(f"[backup-db] wrote {dest}")
    return 0


def cmd_retention_run(args) -> int:
    """Invoke webdb.prune_old using config.ini or CLI overrides and print a JSON result."""
    cfg = _load_config("config.ini")
    alerts_days = args.alerts_days
    blocks_days = args.blocks_days
    if alerts_days is None:
        alerts_days = cfg.getint("Retention", "AlertsDays", fallback=0)
    if blocks_days is None:
        blocks_days = cfg.getint("Retention", "BlocksDays", fallback=0)
    if hasattr(webdb, "prune_old"):
        res = webdb.prune_old(
            days_alerts=int(alerts_days), days_blocks=int(blocks_days)
        )
        print(
            json.dumps(
                {
                    "ok": True,
                    "deleted": res,
                    "settings": {
                        "alerts_days": int(alerts_days),
                        "blocks_days": int(blocks_days),
                    },
                }
            )
        )
        return 0
    print(json.dumps({"ok": False, "error": "retention_unsupported"}))
    return 1


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    cfg = _load_config("config.ini")
    args = build_arg_parser(cfg).parse_args(argv)
    monitor = NetworkMonitor(cfg)
    try:
        if args.mode == "train":
            if getattr(args, "until_ctrl_c", False):
                monitor.capture_and_train_until_interrupt(
                    interface=args.interface,
                    model_path=args.model,
                    min_packets=getattr(args, "min_packets", 100),
                )
            else:
                monitor.capture_and_train(
                    interface=args.interface,
                    packet_count=args.count,
                    model_path=args.model,
                )
        elif args.mode == "monitor":
            _start_api_server_in_background()
            monitor.start_monitoring(
                interface=args.interface,
                model_path=args.model,
                firewall_blocking=getattr(args, "firewall_blocking", False),
                simulate=getattr(args, "simulate_traffic", False),
            )
        elif args.mode == "verify-model":
            # Create a detector aligned with config, load bundle, and print details
            det = AnomalyDetector(
                contamination=cfg.getfloat(
                    "IsolationForest", "Contamination", fallback=0.05
                ),
                n_estimators=cfg.getint("IsolationForest", "NEstimators", fallback=200),
                random_state=cfg.getint("IsolationForest", "RandomState", fallback=42),
            )
            det.load_model(args.model)

            info = cast(Dict[str, Any], det.bundle_metadata())

            print("Model bundle info")
            print("-----------------")
            print(f"Version:          {info.get('version', '')}")
            print(f"Trained at:       {info.get('trained_at', '')}")

            params = cast(Dict[str, Any], info.get("params", {}) or {})

            print(
                f"IF params:        contamination={params.get('contamination')}  "
                f"n_estimators={params.get('n_estimators')}  random_state={params.get('random_state')}"
            )
            print(f"Feature count:    {info.get('feature_count', 0)}")
            print(f"Feature checksum: {info.get('feature_checksum', '')}")

            names = cast(List[str], info.get("feature_names", []) or [])

            print("Feature order:    " + (", ".join(names) if names else "<none>"))
            return 0

        elif args.mode == "config-validate":  # NEW
            print("Config OK")
            return 0
        elif args.mode == "backup-db":
            return cmd_backup_db(args)
        elif args.mode == "retention-run":
            return cmd_retention_run(args)
        else:
            print("Unknown mode. Use 'train' or 'monitor'.")
            return 2
    except PermissionError:
        print(
            "[ERROR] Permission denied. Try running with elevated privileges (e.g., sudo) for packet capture."
        )
        return 1
    except FileNotFoundError as e:
        print(f"[ERROR] {e}")
        return 1
    except ValueError as e:
        print(f"[ERROR] {e}")
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        return 0
    except Exception as e:
        print(f"[ERROR] {e}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
