import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta, timezone
import uuid, hashlib, os

DB = Path("ids_web.db")
SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY, ts TEXT, src_ip TEXT, label TEXT, severity TEXT, kind TEXT
);
CREATE TABLE IF NOT EXISTS blocks (
  id TEXT PRIMARY KEY, ts TEXT, ip TEXT, action TEXT, reason TEXT
);
CREATE TABLE IF NOT EXISTS devices (
  ip TEXT PRIMARY KEY,
  first_seen TEXT,
  last_seen TEXT,
  name TEXT,
  open_ports TEXT, 
  risk TEXT       
);
-- New (additive) tables – safe to create if missing

CREATE TABLE IF NOT EXISTS auth_users (
  username TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_lockout (
  username TEXT PRIMARY KEY,
  fail_count INTEGER NOT NULL DEFAULT 0,
  last_fail_at TEXT,
  locked_until TEXT
);
CREATE TABLE IF NOT EXISTS trusted_ips (
  ip TEXT PRIMARY KEY,
  note TEXT,
  created_ts TEXT
);

"""

def _con():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con

def init():
    DB.parent.mkdir(parents=True, exist_ok=True)
    with closing(_con()) as con:
        con.executescript(SCHEMA)
        # --- migration: add 'reason' column if the table already exists without it ---
        cols = [r[1] for r in con.execute("PRAGMA table_info(blocks)")]
        if "reason" not in cols:
            con.execute("ALTER TABLE blocks ADD COLUMN reason TEXT DEFAULT ''")
        # --- migration: add 'open_ports'/'risk' to devices if missing ---
        dcols = [r[1] for r in con.execute("PRAGMA table_info(devices)")]
        if "open_ports" not in dcols:
            con.execute("ALTER TABLE devices ADD COLUMN open_ports TEXT DEFAULT ''")
        if "risk" not in dcols:
            con.execute("ALTER TABLE devices ADD COLUMN risk TEXT DEFAULT ''")
        bcols = [r[1] for r in con.execute("PRAGMA table_info(blocks)")]
        if "expires_at" not in bcols:
            con.execute("ALTER TABLE blocks ADD COLUMN expires_at TEXT DEFAULT ''")
        con.commit()

def list_alerts(limit: int = 100, cursor: Optional[str] = None):
    """
    Backward compatible. If cursor is provided (ISO timestamp), returns rows with ts < cursor.
    """
    with closing(_con()) as con:
        if cursor:
            rows = con.execute(
                "SELECT * FROM alerts WHERE ts < ? ORDER BY ts DESC LIMIT ?",
                (cursor, limit),
            )
        else:
            rows = con.execute(
                "SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (limit,)
            )
        return [dict(r) for r in rows]

def list_blocks(limit=100):
    with closing(_con()) as con:
        return [
            dict(r)
            for r in con.execute(
                "SELECT * FROM blocks ORDER BY ts DESC LIMIT ?", (limit,)
            )
        ]

def delete_blocks_by_ip(ip: str):
    with closing(_con()) as con:
        con.execute("DELETE FROM blocks WHERE ip = ? AND action = 'block'", (ip,))
        con.commit()

def delete_action_by_ip(ip: str, action: str):
    with closing(_con()) as con:
        con.execute("DELETE FROM blocks WHERE ip = ? AND action = ?", (ip, action))
        con.commit()

def insert_alert(a):
    with closing(_con()) as con:
        con.execute(
            "INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?)",
            (a["id"], a["ts"], a["src_ip"], a["label"], a["severity"], a["kind"]),
        )
        con.commit()

def insert_block(b):
    with closing(_con()) as con:
        con.execute(
            "INSERT OR REPLACE INTO blocks (id, ts, ip, action, reason) VALUES (?,?,?,?,?)",
            (b["id"], b["ts"], b["ip"], b["action"], b.get("reason", "")),
        )
        con.commit()

# -----------------------
# New convenience helpers
# -----------------------

def add_alert(
    *,
    src_ip: str,
    dest_ip: str = "",   # ignored by current schema (kept for API compatibility)
    dport: int = 0,      # ignored
    severity: str,
    kind: str,
    label: str = "",
    message: str = "",   # ignored
    ts: Optional[str] = None,
) -> str:
    """
    Rich signature compatible with the API sink, but stores only the 6 columns your table has.
    """
    rid = uuid.uuid4().hex
    ts = ts or datetime.utcnow().isoformat(timespec="seconds") + "Z"
    insert_alert({
        "id": rid,
        "ts": ts,
        "src_ip": src_ip,
        "label": label or kind,
        "severity": severity,
        "kind": kind,
    })
    return rid

# ---- Device inventory (additive table; safe) ----

def list_log_events(limit: int = 200):
    with closing(_con()) as con:
        rows = con.execute(
            """
            SELECT id, ts, src_ip AS ip, 'alert' AS type, label, severity, kind
              FROM alerts
            UNION ALL
            SELECT id, ts, ip, 'block' AS type, action AS label, NULL AS severity, 'block' AS kind
              FROM blocks
            ORDER BY ts DESC
            LIMIT ?
            """,
            (int(limit),),
        )
        return [dict(r) for r in rows]

# --- add below your existing list_log_events() (or replace it with this superset) ---
def list_log_events_filtered(
    *,
    limit: int = 200,
    ip: str | None = None,
    severity: str | None = None,   # e.g., low|medium|high|critical (case-insensitive)
    kind: str | None = None,       # 'alert' or 'block'
    ts_from: str | None = None,    # ISO 8601 (inclusive)
    ts_to: str | None = None       # ISO 8601 (inclusive)
):
    clauses = []
    params = []

    # We UNION alerts + blocks into a normalized view with a few columns
    base = """
      SELECT id, ts, src_ip AS ip, 'alert' AS type, label, severity, kind
        FROM alerts
      UNION ALL
      SELECT id, ts, ip, 'block' AS type, action AS label, NULL AS severity, 'block' AS kind
        FROM blocks
    """
    where = []
    if ip:
        where.append("ip = ?")
        params.append(ip)
    if severity:
        where.append("LOWER(COALESCE(severity,'')) = LOWER(?)")
        params.append(severity)
    if kind:
        where.append("LOWER(type) = LOWER(?)")
        params.append(kind)
    if ts_from:
        where.append("ts >= ?")
        params.append(ts_from)
    if ts_to:
        where.append("ts <= ?")
        params.append(ts_to)

    q = f"SELECT * FROM ({base})"
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY ts DESC LIMIT ?"
    params.append(int(limit))

    with closing(_con()) as con:
        rows = con.execute(q, tuple(params))
        return [dict(r) for r in rows]

# ---- Optional DB-backed auth helpers (not required by your current API) ----

def _hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()

def ensure_admin(username: str = "admin", password: Optional[str] = None) -> None:
    pw = password or os.environ.get("ADMIN_PASSWORD")
    if not pw:
        return
    with closing(_con()) as con:
        r = con.execute("SELECT username FROM auth_users WHERE username=?", (username,)).fetchone()
        if r is None:
            con.execute(
                "INSERT INTO auth_users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, _hash_password(pw), datetime.utcnow().isoformat(timespec='seconds') + "Z"),
            )
            con.commit()

def verify_login(username: str, password: str) -> bool:
    with closing(_con()) as con:
        row = con.execute("SELECT password_hash FROM auth_users WHERE username=?", (username,)).fetchone()
        if not row:
            return False
        return _hash_password(password) == row["password_hash"]

def register_failure(username: str, lock_after: int = 5, lock_minutes: int = 15) -> None:
    now = datetime.utcnow()
    with closing(_con()) as con:
        r = con.execute("SELECT * FROM auth_lockout WHERE username=?", (username,)).fetchone()
        if r is None:
            con.execute(
                "INSERT INTO auth_lockout (username, fail_count, last_fail_at) VALUES (?, ?, ?)",
                (username, 1, now.isoformat(timespec='seconds') + "Z"),
            )
        else:
            count = int(r["fail_count"]) + 1
            locked_until = None
            if count >= lock_after:
                locked_until = (now + timedelta(minutes=lock_minutes)).isoformat(timespec='seconds') + "Z"
                count = 0
            con.execute(
                "UPDATE auth_lockout SET fail_count=?, last_fail_at=?, locked_until=? WHERE username=?",
                (count, now.isoformat(timespec='seconds') + "Z", locked_until, username),
            )
        con.commit()

def clear_failures(username: str) -> None:
    with closing(_con()) as con:
        con.execute("DELETE FROM auth_lockout WHERE username=?", (username,))
        con.commit()

def is_locked(username: str) -> Optional[str]:
    with closing(_con()) as con:
        r = con.execute("SELECT locked_until FROM auth_lockout WHERE username=?", (username,)).fetchone()
        if not r:
            return None
        lu = r["locked_until"]
        if not lu:
            return None
        return lu
    
# ---------------- Devices ----------------

def _now():
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"

def upsert_device(ip: str, name: str = ""):
    """Create if missing; always refresh last_seen; set name if provided."""
    ts = _now()
    with closing(_con()) as con:
        con.execute(
            """
            INSERT INTO devices (ip, first_seen, last_seen, name)
            VALUES (?,?,?,?)
            ON CONFLICT(ip) DO UPDATE SET
              last_seen=excluded.last_seen,
              name=CASE WHEN excluded.name <> '' THEN excluded.name ELSE devices.name END
            """,
            (ip, ts, ts, name or ""),
        )
        con.commit()

def set_device_name(ip: str, name: str):
    with closing(_con()) as con:
        con.execute("UPDATE devices SET name = ? WHERE ip = ?", (name, ip))
        con.commit()

def list_devices(limit: int = 200):
    with closing(_con()) as con:
        rows = con.execute(
            "SELECT * FROM devices ORDER BY last_seen DESC LIMIT ?",
            (int(limit),),
        )
        return [dict(r) for r in rows]

def record_device(ip: str, name: str = ""):
    if not ip:
        return
    upsert_device(ip, name or "")

# --- Scan results helpers ---
def set_device_scan(ip: str, ports_csv: str, risk: str = ""):
    if not ip:
        return
    with closing(_con()) as con:
        # Ensure the device exists; set first/last seen if newly inserted
        con.execute(
            "INSERT OR IGNORE INTO devices (ip, first_seen, last_seen, name, open_ports, risk) "
            "VALUES (?, datetime('now'), datetime('now'), '', '', '')",
            (ip,),
        )
        # Update scan results and touch last_seen
        con.execute(
            "UPDATE devices SET open_ports = ?, risk = ?, last_seen = datetime('now') WHERE ip = ?",
            (ports_csv or "", (risk or ""), ip),
        )
        con.commit()

def upsert_trusted_ip(ip: str, note: str = ""):
    with closing(_con()) as con:
        con.execute(
            "INSERT OR REPLACE INTO trusted_ips (ip, note, created_ts) VALUES (?, ?, datetime('now'))",
            (ip, note or ""),
        )
        con.commit()

def remove_trusted_ip(ip: str):
    with closing(_con()) as con:
        con.execute("DELETE FROM trusted_ips WHERE ip=?", (ip,))
        con.commit()

def list_trusted_ips():
    with closing(_con()) as con:
        return [dict(r) for r in con.execute("SELECT * FROM trusted_ips ORDER BY ip")]

def is_trusted(ip: str) -> bool:
    with closing(_con()) as con:
        r = con.execute("SELECT 1 FROM trusted_ips WHERE ip=?", (ip,)).fetchone()
        return bool(r)

# auto-expire temporary bans: if latest action for an IP is a 'block' with past expires_at
def expire_bans(now_iso: str):
    with closing(_con()) as con:
        rows = con.execute(
            """
            SELECT b.*
              FROM blocks b
             WHERE b.action='block'
               AND COALESCE(b.expires_at,'') <> ''
               AND b.expires_at < ?
               AND NOT EXISTS (
                 SELECT 1 FROM blocks b2
                  WHERE b2.ip=b.ip AND b2.ts > b.ts
               )
            """,
            (now_iso,),
        ).fetchall()
        for r in rows:
            con.execute(
                "INSERT OR REPLACE INTO blocks (id, ts, ip, action, reason, expires_at) VALUES (?,?,?,?,?,?)",
                (uuid.uuid4().hex, now_iso, r["ip"], "unblock", "auto-expired", ""),
            )
        con.commit()

# (tweak) widen insert_block to support expires_at
def insert_block(b):
    with closing(_con()) as con:
        con.execute(
            "INSERT OR REPLACE INTO blocks (id, ts, ip, action, reason, expires_at) VALUES (?,?,?,?,?,?)",
            (b["id"], b["ts"], b["ip"], b["action"], b.get("reason", ""), b.get("expires_at", "")),
        )
        con.commit()

# optional retention helper (used by PD-29)
def prune_old(days_alerts: int | None = None, days_blocks: int | None = None) -> dict:
    out = {"alerts": 0, "blocks": 0}
    with closing(_con()) as con:
        if days_alerts and days_alerts > 0:
            cur = con.execute("DELETE FROM alerts WHERE ts < datetime('now', ?)", (f'-{int(days_alerts)} days',))
            out["alerts"] = cur.rowcount
        if days_blocks and days_blocks > 0:
            cur = con.execute("DELETE FROM blocks WHERE ts < datetime('now', ?)", (f'-{int(days_blocks)} days',))
            out["blocks"] = cur.rowcount
        con.commit()
    return out

def wipe_all() -> Dict[str, int]:
    """Clear alerts, blocks, devices, and trusted IPs in one transaction."""
    tables = (
        ("alerts", "alerts"),
        ("blocks", "blocks"),
        ("devices", "devices"),
        ("trusted_ips", "trusted"),
    )
    cleared: Dict[str, int] = {}
    with closing(_con()) as con:
        for table, key in tables:
            cur = con.execute(f"DELETE FROM {table}")
            cleared[key] = cur.rowcount
        con.commit()
    return cleared