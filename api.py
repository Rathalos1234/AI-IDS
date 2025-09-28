from flask import Flask, request, jsonify
from flask import session, abort
from flask_cors import CORS
from datetime import datetime, timedelta
import os, configparser
import uuid
import webdb
from flask import Response, stream_with_context
import json, time


app = Flask(__name__)
CORS(app)
webdb.init()

# =========================
# Auth (minimal) + lockout
# =========================
# These defaults preserve current behavior (no auth required).
app.secret_key = os.environ.get("APP_SECRET", "dev-secret")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
LOCK_AFTER = int(os.environ.get("LOCK_AFTER", "5"))
LOCK_MINUTES = int(os.environ.get("LOCK_MINUTES", "15"))
REQUIRE_AUTH = os.environ.get("REQUIRE_AUTH", "0") == "1"

_LOCKS = {}  # {username: {"fail_count": int, "locked_until": iso_str}}

def _is_locked(username: str):
    rec = _LOCKS.get(username)
    if not rec or not rec.get("locked_until"):
        return None
    until = datetime.fromisoformat(rec["locked_until"])
    if until > datetime.utcnow():
        return until.isoformat() + "Z"
    return None

def _register_failure(username: str):
    now = datetime.utcnow()
    rec = _LOCKS.get(username, {"fail_count": 0, "locked_until": None})
    count = int(rec.get("fail_count", 0)) + 1
    locked_until = rec.get("locked_until")
    if count >= LOCK_AFTER:
        locked_until = (now + timedelta(minutes=LOCK_MINUTES)).isoformat()
        count = 0
    _LOCKS[username] = {"fail_count": count, "locked_until": locked_until}

def _clear_failures(username: str):
    _LOCKS.pop(username, None)

def _verify_login(username: str, password: str) -> bool:
    return username == ADMIN_USER and password == ADMIN_PASSWORD

def require_auth():
    if not REQUIRE_AUTH:
        return
    if not session.get("username"):
        abort(401)

@app.post("/api/auth/login")
def login():
    data = request.get_json(force=True, silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", "")).strip()
    if not username or not password:
        return jsonify({"ok": False, "error": "missing credentials"}), 400
    lu = _is_locked(username)
    if lu:
        return jsonify({"ok": False, "error": "locked", "locked_until": lu}), 403
    if not _verify_login(username, password):
        _register_failure(username)
        return jsonify({"ok": False, "error": "invalid"}), 403
    _clear_failures(username)
    session["username"] = username
    return jsonify({"ok": True, "user": username})

@app.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/alerts")
def alerts():
    return jsonify(webdb.list_alerts(limit=int(request.args.get("limit", 100))))


@app.get("/api/blocks")
def blocks():
    return jsonify(webdb.list_blocks(limit=int(request.args.get("limit", 100))))


@app.post("/api/block")
def post_block():
    body = request.get_json(force=True) or {}
    ip = (body.get("ip") or "").strip()
    if not ip:
        return {"error": "ip required"}, 400

    webdb.delete_action_by_ip(ip, "unblock")
    webdb.delete_action_by_ip(ip, "block")
    webdb.insert_block(
        {
            "id": str(uuid.uuid4()),
            "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "ip": ip,
            "action": "block",
        }
    )
    return {"ok": True}


@app.post("/api/unblock")
def post_unblock():
    body = request.get_json(force=True) or {}
    ip = (body.get("ip") or "").strip()
    if not ip:
        return {"error": "ip required"}, 400

    webdb.delete_action_by_ip(ip, "block")
    webdb.delete_action_by_ip(ip, "unblock")
    webdb.insert_block(
        {
            "id": str(uuid.uuid4()),
            "ts": datetime.now().isoformat(timespec="seconds") + "Z",
            "ip": ip,
            "action": "unblock",
        }
    )
    return {"ok": True}

# =========================
# New: stats snapshot
# =========================
@app.get("/api/stats")
def stats():
    require_auth()
    a = webdb.list_alerts(limit=200)
    b = webdb.list_blocks(limit=200)
    return jsonify({
        "ok": True,
        "counts": {"alerts_200": len(a), "blocks_200": len(b)},
        "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z"
    })

# =========================
# New: settings (GET/PUT)
# =========================
SAFE_KEYS = {
    ("Logging", "LogLevel"),
    ("Logging", "EnableFileLogging"),
    ("Monitoring", "AlertThresholds"),
    ("Signatures", "Enable"),
}

def _load_settings(path: str = "config.ini") -> dict:
    cfg = configparser.ConfigParser()
    cfg.read(path)
    out = {}
    for sec, key in SAFE_KEYS:
        if not cfg.has_section(sec) and sec != "DEFAULT":
            cfg.add_section(sec)
        out[f"{sec}.{key}"] = cfg.get(sec, key, fallback="")
    return out

@app.get("/api/settings")
def get_settings():
    require_auth()
    return jsonify({"ok": True, "settings": _load_settings()})

@app.put("/api/settings")
def put_settings():
    require_auth()
    updates = request.get_json(force=True, silent=True) or {}
    cfg = configparser.ConfigParser()
    cfg.read("config.ini")
    for composed, value in updates.items():
        if "." not in composed:
            continue
        sec, key = composed.split(".", 1)
        if (sec, key) not in SAFE_KEYS:
            return jsonify({"ok": False, "error": f"{sec}.{key} is not writable"}), 400
        if not cfg.has_section(sec) and sec != "DEFAULT":
            cfg.add_section(sec)
        cfg.set(sec, key, str(value))
    try:
        from config_validation import validate_config
        validate_config(cfg)
    except Exception as e:
        return jsonify({"ok": False, "error": f"Invalid config update: {e}"}), 400
    with open("config.ini", "w") as fh:
        cfg.write(fh)
    return jsonify({"ok": True})

# =========================
# New: devices listing
# =========================
@app.get("/api/devices")
def devices():
    require_auth()
    try:
        items = webdb.list_devices(limit=200)
    except Exception:
        items = []
    return jsonify({"ok": True, "items": items})


@app.get("/api/logs")
def get_logs():
    require_auth()
    limit = int(request.args.get("limit", 200))
    return jsonify({"ok": True, "items": webdb.list_log_events(limit=limit)})

@app.get("/api/events")
def sse_events():
    require_auth()
    def gen():
        last_alert_id = None
        last_block_id = None
        # immediate keep-alive
        yield ": ok\n\n"
        while True:
            # newest alert
            a = webdb.list_alerts(limit=1)
            if a and a[0]["id"] != last_alert_id:
                last_alert_id = a[0]["id"]
                yield f"event: alert\ndata: {json.dumps(a[0])}\n\n"
            # newest block/unblock
            b = webdb.list_blocks(limit=1)
            if b and b[0]["id"] != last_block_id:
                last_block_id = b[0]["id"]
                yield f"event: block\ndata: {json.dumps(b[0])}\n\n"
            # heartbeat (helps some proxies)
            yield ": ping\n\n"
            time.sleep(1.5)

    resp = Response(stream_with_context(gen()), mimetype="text/event-stream")
    resp.headers["Cache-Control"] = "no-cache"
    resp.headers["X-Accel-Buffering"] = "no"  # nginx
    return resp


if __name__ == "__main__":
    app.run("127.0.0.1", 5000, debug=True)


