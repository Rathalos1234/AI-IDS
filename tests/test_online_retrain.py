import os
import time
import subprocess
import configparser
# import signal
# import pathlib

MODEL = "models/iforest.joblib"


def _mtime(path):
    try:
        return os.path.getmtime(path)
    except (FileNotFoundError, PermissionError, OSError):
        return 0


def test_online_retrain_smoke(tmp_path):
    # Precondition: config.ini has
    # [Training] SaveRollingParquet=true ; RollingParquetPath=data/rolling.parquet
    # [Monitoring] OnlineRetrainInterval=50  (or small)
    #
    # NOTE: This test temporarily modifies config.ini to use a low retrain interval
    # and simulation mode to ensure packets are generated quickly enough.

    # Read current config and save original values for restoration
    cfg = configparser.ConfigParser()
    cfg.read("config.ini")

    orig_interval = cfg.get("Monitoring", "onlineretraininterval", fallback="100")
    orig_simulate = cfg.get("Monitoring", "simulatetraffic", fallback="false")

    try:
        # Temporarily set test friendly values: low interval + simulation mode
        if "Monitoring" not in cfg.sections():
            cfg.add_section("Monitoring")

        cfg.set("Monitoring", "onlineretraininterval", "10")  # Only need 10 packets
        cfg.set("Monitoring", "simulatetraffic", "true")  # Auto-generate packets

        with open("config.ini", "w") as f:
            cfg.write(f)

        before = _mtime(MODEL)

        # Start monitor (stdout shows "Online retraining …" when it fires)
        proc = subprocess.Popen(
            ["python", "main.py", "monitor", "-i", "lo", "-m", MODEL],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        saw_retrain = False
        deadline = time.time() + 75  # ~1 minute window
        while time.time() < deadline:
            line = proc.stdout.readline() if proc.stdout else ""
            if "Online retraining" in line or "model saved to" in line:
                saw_retrain = True
                break
            time.sleep(0.5)

        # Stop monitor
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            proc.kill()

        after = _mtime(MODEL)

        # Accept either signal as pass: log shows retrain OR model file mtime increased
        assert saw_retrain or after > before, (
            f"Expected retrain; before={before}, after={after}"
        )

    finally:
        # restore original config values
        cfg.set("Monitoring", "onlineretraininterval", orig_interval)
        cfg.set("Monitoring", "simulatetraffic", orig_simulate)

        with open("config.ini", "w") as f:
            cfg.write(f)
