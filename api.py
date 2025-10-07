from flask import Flask, request, jsonify
from flask import session, abort
from flask_cors import CORS
from datetime import datetime, timedelta
import os, configparser
import uuid
import webdb
from flask import Response, stream_with_context, send_file
import json, time
import socket, ipaddress, threading
from io import StringIO
import csv
from ipaddress import ip_address
from typing import Optional
import tempfile, shutil

app = Flask(__name__)
# allow cookies when UI is on a different origin during dev
CORS(app, supports_credentials=True)
webdb.init()

# --- PD-29: record app start for uptime ---
_APP_STARTED = datetime.utcnow()


# =========================
# PD-28 helpers (safe fallbacks)
# =========================
# In-memory trusted list + temporary bans if webdb lacks native support.
_TRUSTED_MEM: set[str] = set()
_TEMP_BANS: dict[str, str] = {}  # ip -> expires_at ISO

def _supports_trusted_db() -> bool:
    return all(hasattr(webdb, name) for name in (
        "list_trusted_ips", "upsert_trusted_ip", "remove_trusted_ip", "is_trusted"
    ))

def _supports_expire_bans() -> bool:
    return hasattr(webdb, "expire_bans")

def _is_trusted(ip: str) -> bool:
    if _supports_trusted_db():
        try:
            return bool(webdb.is_trusted(ip))
        except Exception:
            return ip in _TRUSTED_MEM
    return ip in _TRUSTED_MEM

def _compute_expiry(body: dict) -> str:
    """Return ISO 'expires_at' or empty string for permanent bans."""
    mins = body.get("duration_minutes")
    if mins is None or str(mins).strip() == "":
        return ""
    try:
        mins = int(mins)
        if mins <= 0:
            return ""
        return datetime.utcnow().isoformat(timespec="seconds") + "Z" if mins == 0 else \
               (datetime.utcnow() + timedelta(minutes=mins)).isoformat(timespec="seconds") + "Z"
    except Exception:
        return ""

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
# session TTL + cookie hygiene
SESSION_TTL = int(os.environ.get("SESSION_TTL_SECONDS", "3600"))
app.permanent_session_lifetime = timedelta(seconds=SESSION_TTL)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(int(os.environ.get("COOKIE_SECURE", "0"))),
)
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

# gate ALL /api/* calls when auth is enabled, except /api/auth/*
@app.before_request
def _gate_api_when_auth_on():
    if not REQUIRE_AUTH:
        return
    p = request.path or ""
    if p.startswith("/api/") and not p.startswith("/api/auth/"):
        if not session.get("username"):
            return jsonify({"ok": False, "error": "unauthorized"}), 401
    # (UI static is served by Vite/Flask separately; nothing else to allow here)

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
    session.clear()
    session.permanent = True
    session["username"] = username
    return jsonify({"ok": True, "user": username})

@app.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify({"ok": True})

@app.get("/api/auth/me")
def whoami():
    if REQUIRE_AUTH and not session.get("username"):
        return jsonify({"ok": False, "user": None}), 401
    return jsonify({"ok": True, "user": session.get("username")})

@app.get("/api/alerts")
def alerts():
    return jsonify(webdb.list_alerts(limit=int(request.args.get("limit", 100))))


@app.get("/api/blocks")
def blocks():
    # Auto-expire temporary bans before listing
    now_iso = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    if _supports_expire_bans():
        try:
            webdb.expire_bans(now_iso)
        except Exception:
            pass
    else:
        # Fallback: expire using in-memory map
        try:
            current = webdb.list_blocks(limit=1000)
            latest_action = {}
            for b in current:
                latest_action.setdefault(b["ip"], b["action"])
            for ip, exp in list(_TEMP_BANS.items()):
                if exp and exp <= now_iso and latest_action.get(ip) == "block":
                    webdb.insert_block({
                        "id": uuid.uuid4().hex,
                        "ts": now_iso,
                        "ip": ip,
                        "action": "unblock",
                        "reason": "auto-expired",
                    })
                    _TEMP_BANS.pop(ip, None)
        except Exception:
            pass
    return jsonify(webdb.list_blocks(limit=int(request.args.get("limit", 100))))
 

@app.post("/api/block")
def post_block():
    body = request.get_json(force=True) or {}
    ip = (body.get("ip") or "").strip()
    if not ip:
        return {"error": "ip required"}, 400
    # PD-28: don't allow blocking trusted IPs
    if _is_trusted(ip):
        return jsonify({"ok": False, "error": "trusted_ip"}), 400
    expires_at = _compute_expiry(body)

    webdb.delete_action_by_ip(ip, "unblock")
    webdb.delete_action_by_ip(ip, "block")
    webdb.insert_block({
        "id": str(uuid.uuid4()),
        "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "ip": ip,
        "action": "block",
        "reason": (body.get("reason") or "").strip(),
        # If webdb has no 'expires_at' column, this extra key is ignored.
        "expires_at": expires_at,
    })
    if expires_at and not _supports_expire_bans():
        _TEMP_BANS[ip] = expires_at
    return {"ok": True}

@app.post("/api/blocks")
def post_block_with_reason():
    """Canonical block endpoint that explicitly supports 'reason'."""
    body = request.get_json(force=True) or {}
    ip = (body.get("ip") or "").strip()
    if not ip:
        return {"error": "ip required"}, 400
    reason = (body.get("reason") or "").strip()
    # PD-28: block guard for trusted IPs + duration support
    if _is_trusted(ip):
        return jsonify({"ok": False, "error": "trusted_ip"}), 400
    expires_at = _compute_expiry(body)

    webdb.delete_action_by_ip(ip, "unblock")
    webdb.delete_action_by_ip(ip, "block")
    webdb.insert_block({
        "id": str(uuid.uuid4()),
        "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "ip": ip,
        "action": "block",
        "reason": reason,
        "expires_at": expires_at,  # <-- persist temp ban
    })
    if expires_at and not _supports_expire_bans():
        _TEMP_BANS[ip] = expires_at
    return {"ok": True}


@app.post("/api/unblock")
def post_unblock():
    body = request.get_json(force=True) or {}
    ip = (body.get("ip") or "").strip()
    if not ip:
        return {"error": "ip required"}, 400

    webdb.delete_action_by_ip(ip, "block")
    webdb.delete_action_by_ip(ip, "unblock")
    webdb.insert_block({
        "id": str(uuid.uuid4()),
        # use UTC for consistent ordering across endpoints
        "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "ip": ip,
        "action": "unblock",
        "reason": (body.get("reason") or "").strip(),
        "expires_at": "",
    })
    _TEMP_BANS.pop(ip, None)  # clear any in-memory duration
    return {"ok": True}

#@app.get("/api/devices")
#def get_devices():
#    limit = int(request.args.get("limit", 200))
#    return jsonify({"ok": True, "items": webdb.list_devices(limit=limit)})

@app.put("/api/device")
def put_device_name():
    """Optional: set a friendly name for a device."""
    body = request.get_json(force=True) or {}
    ip = (body.get("ip") or "").strip()
    name = (body.get("name") or "").strip()
    if not ip:
        return {"error": "ip required"}, 400
    if name:
        webdb.set_device_name(ip, name)
    else:
        webdb.upsert_device(ip)  # ensure it exists / refresh last_seen
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

# PD-29: retention window settings (days)
SAFE_KEYS.update({
    ("Retention", "AlertsDays"),
    ("Retention", "BlocksDays"),
})


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

# =========================
# PD-29: Ops – health, retention, DB backup
# =========================
@app.get("/healthz")
def healthz():
    """Basic healthcheck with DB probe and uptime in seconds."""
    try:
        # lightweight DB touch
        webdb.list_alerts(limit=1)
        db_ok = True
    except Exception:
        db_ok = False
    return jsonify({
        "ok": db_ok,
        "uptime_sec": int((datetime.utcnow() - _APP_STARTED).total_seconds()),
        "time": datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }), (200 if db_ok else 500)

@app.post("/api/retention/run")
def retention_run():
    """Prune old rows based on Retention.* days in config.ini."""
    require_auth()
    # read current settings using existing loader
    s = _load_settings()
    alerts_days = int((s.get("Retention.AlertsDays") or 0) or 0)
    blocks_days = int((s.get("Retention.BlocksDays") or 0) or 0)
    if hasattr(webdb, "prune_old"):
        res = webdb.prune_old(days_alerts=alerts_days, days_blocks=blocks_days)
        return jsonify({"ok": True, "deleted": res, "settings": {"alerts_days": alerts_days, "blocks_days": blocks_days}})
    else:
        # graceful fallback if webdb lacks helper
        return jsonify({"ok": False, "error": "retention_unsupported", "settings": {"alerts_days": alerts_days, "blocks_days": blocks_days}}), 501

@app.get("/api/backup/db")
def backup_db():
    """Send a safe copy of the SQLite DB to the client."""
    require_auth()
    db_path = str(webdb.DB)
    tmpdir = tempfile.mkdtemp(prefix="idsdb_")
    fname = f"ids_web_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.sqlite"
    tmpfile = os.path.join(tmpdir, fname)
    shutil.copyfile(db_path, tmpfile)
    # stream the temp copy; OS/tempdir cleanup is fine for dev
    return send_file(tmpfile, as_attachment=True, download_name=fname, mimetype="application/octet-stream")


# =========================
# PD-28: Trusted IPs CRUD
# =========================
@app.get("/api/trusted")
def get_trusted():
    require_auth()
    if _supports_trusted_db():
        items = webdb.list_trusted_ips()
    else:
        # fallback view
        items = [{"ip": ip, "note": "", "created_ts": None} for ip in sorted(_TRUSTED_MEM)]
    return jsonify({"ok": True, "items": items})

@app.post("/api/trusted")
def add_trusted():
    require_auth()
    body = request.get_json(force=True) or {}
    ip = (body.get("ip") or "").strip()
    note = (body.get("note") or "").strip()
    if not ip:
        return jsonify({"ok": False, "error": "ip_required"}), 400
    # validate IP format
    try:
        ipaddress.ip_address(ip)
    except Exception:
        return jsonify({"ok": False, "error": "bad_ip"}), 400
    if _supports_trusted_db():
        webdb.upsert_trusted_ip(ip, note)
    else:
        _TRUSTED_MEM.add(ip)
    return jsonify({"ok": True})

@app.delete("/api/trusted/<ip>")
def del_trusted(ip):
    require_auth()
    if _supports_trusted_db():
        webdb.remove_trusted_ip(ip)
    else:
        _TRUSTED_MEM.discard(ip)
    return jsonify({"ok": True})


# =========================
# Active scan (PD-26)
# =========================
_SCAN = {
    "status": "idle",   # idle | running | done | error
    "started": None,
    "finished": None,
    "progress": 0,
    "total": 0,
    "message": "",
}
_SCAN_LOCK = threading.Lock()

TOP_PORTS = [22, 23, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5900]

def _risk_from_ports(ports: list[int]) -> str:
    if any(p in ports for p in (23, 445, 3389, 5900, 21)):
        return "High"
    if ports:
        return "Medium"
    return "Low"

def _tcp_scan(ip: str, ports: list[int], timeout_ms: int) -> list[int]:
    openp = []
    to = max(50, min(timeout_ms, 1000)) / 1000.0
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(to)
            if s.connect_ex((ip, p)) == 0:
                openp.append(p)
        except Exception:
            pass
        finally:
            try: s.close()
            except Exception: pass
    return openp

def _scan_job(target_ips: list[str], ports: list[int], timeout_ms: int):
    with _SCAN_LOCK:
        _SCAN.update({
            "status": "running",
            "started": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "finished": None,
            "progress": 0,
            "total": len(target_ips),
            "message": "",
        })
    try:
        done = 0
        for ip in target_ips:
            openp = _tcp_scan(ip, ports, timeout_ms)
            webdb.set_device_scan(ip, ",".join(map(str, openp)), _risk_from_ports(openp))
            done += 1
            with _SCAN_LOCK:
                _SCAN["progress"] = done
        with _SCAN_LOCK:
            _SCAN["status"] = "done"
            _SCAN["finished"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    except Exception as e:
        with _SCAN_LOCK:
            _SCAN["status"] = "error"
            _SCAN["message"] = str(e)
            _SCAN["finished"] = datetime.utcnow().isoformat(timespec="seconds") + "Z"

@app.post("/api/scan")
def start_scan():
    """Start a bounded TCP scan over devices or a CIDR. Returns immediately."""
    require_auth()
    body = request.get_json(silent=True) or {}
    # Targets: CIDR (if provided) else known devices
    target_ips: list[str] = []
    cidr = (body.get("cidr") or "").strip()
    if cidr:
        try:
            # Accept a single IP or a CIDR. For /32 (or /128), include the single address.
            try:
                # If this succeeds, user gave a single IP (no slash)
                ip_obj = ipaddress.ip_address(cidr)
                target_ips = [str(ip_obj)]
            except ValueError:
                net = ipaddress.ip_network(cidr, strict=False)
                hosts = list(net.hosts())
                if not hosts:
                    # /32 IPv4 (or /128 IPv6): include the network address itself
                    hosts = [net.network_address]
                # safety cap: max 256 hosts
                for i, ip in enumerate(hosts):
                    if i >= 256: break
                    target_ips.append(str(ip))
        except Exception:
            return jsonify({"ok": False, "error": "bad_cidr"}), 400
    else:
        # include loopback (127.0.0.0/8) in dev so local services can be scanned
        target_ips = [
            d["ip"] for d in webdb.list_devices(limit=1000)
            if d.get("ip") and (
                ipaddress.ip_address(d["ip"]).is_private or d["ip"].startswith("127.")
            )
        ]
        target_ips = list(dict.fromkeys(target_ips))  # dedupe, preserve order
    if not target_ips:
        return jsonify({"ok": False, "error": "no_targets"}), 400

    ports = body.get("ports") or TOP_PORTS
    ports = [int(p) for p in ports][:64]            # safety cap
    # Slightly higher default improves detection on slower stacks
    timeout_ms = int(body.get("timeout_ms") or 500)

    with _SCAN_LOCK:
        if _SCAN["status"] == "running":
            return jsonify({"ok": False, "error": "scan_in_progress"}), 409
        threading.Thread(target=_scan_job, args=(target_ips, ports, timeout_ms), daemon=True).start()
    return jsonify({"ok": True, "targets": len(target_ips), "ports": ports})

@app.get("/api/scan/status")
def scan_status():
    require_auth()
    with _SCAN_LOCK:
        return jsonify({"ok": True, "scan": _SCAN})


# --- PD-29: health alias under /api for dev proxy convenience ---
@app.get("/api/healthz")
def healthz_api():
    return healthz()

@app.get("/api/logs")
def get_logs():
    require_auth()
    q = request.args
    items = webdb.list_log_events_filtered(
        limit=int(q.get("limit", 200)),
        ip=q.get("ip") or None,
        severity=q.get("severity") or None,
        kind=q.get("type") or None,
        ts_from=q.get("from") or None,
        ts_to=q.get("to") or None,
    )
    return jsonify({"ok": True, "items": items})

@app.get("/api/logs/export")
def export_logs():
    require_auth()
    q = request.args
    fmt = (q.get("format") or "csv").lower()
    items = webdb.list_log_events_filtered(
        limit=int(q.get("limit", 10000)),
        ip=q.get("ip") or None,
        severity=q.get("severity") or None,
        kind=q.get("type") or None,
        ts_from=q.get("from") or None,
        ts_to=q.get("to") or None,
    )
    if fmt == "json":
        resp = app.response_class(
            response=json.dumps(items),
            status=200,
            mimetype="application/json",
        )
        resp.headers["Content-Disposition"] = "attachment; filename=logs.json"
        return resp

    # CSV default
    buf = StringIO()
    writer = csv.DictWriter(buf, fieldnames=["id","ts","ip","type","label","severity","kind"])
    writer.writeheader()
    writer.writerows(items)
    resp = app.response_class(buf.getvalue(), mimetype="text/csv")
    resp.headers["Content-Disposition"] = "attachment; filename=logs.csv"
    return resp

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


