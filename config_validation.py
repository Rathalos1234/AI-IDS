# -*- coding: utf-8 -*-
from __future__ import annotations
import configparser

_VALID_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


def validate_config(cfg: configparser.ConfigParser) -> None:
    errs = []

    w = cfg.getint("DEFAULT", "DefaultWindowSize", fallback=500)
    if w <= 0:
        errs.append("DEFAULT.DefaultWindowSize must be > 0")

    cnt = cfg.getint("DEFAULT", "DefaultPacketCount", fallback=1000)
    if cnt <= 0:
        errs.append("DEFAULT.DefaultPacketCount must be > 0")

    cont = cfg.getfloat("IsolationForest", "Contamination", fallback=0.05)
    if not (0.0 < cont <= 0.5):
        errs.append("IsolationForest.Contamination must be in (0.0, 0.5]")

    nest = cfg.getint("IsolationForest", "NEstimators", fallback=200)
    if nest < 10:
        errs.append("IsolationForest.NEstimators must be >= 10")

    lvl = cfg.get("Logging", "LogLevel", fallback="INFO").upper()
    if lvl not in _VALID_LEVELS:
        errs.append(f"Logging.LogLevel must be one of {sorted(_VALID_LEVELS)}")

    thr = cfg.get("Monitoring", "AlertThresholds", fallback="-0.10, -0.05")
    try:
        hi, med = [float(p.strip()) for p in thr.split(",")[:2]]
        if not (hi <= med):
            errs.append(
                "Monitoring.AlertThresholds must be 'high,medium' with high<=medium"
            )
    except Exception:
        errs.append("Monitoring.AlertThresholds must be two floats like '-0.10, -0.05'")

    if errs:
        raise ValueError("Invalid config:\n - " + "\n - ".join(errs))
