import os
import time
import subprocess
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
