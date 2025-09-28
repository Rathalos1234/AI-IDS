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
  id TEXT PRIMARY KEY, ts TEXT, ip TEXT, action TEXT
);

-- New (additive) tables – safe to create if missing
CREATE TABLE IF NOT EXISTS devices (
  ip TEXT PRIMARY KEY,
  first_seen TEXT,
  last_seen TEXT,
  name TEXT
);
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
"""


def _con():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def init():
    DB.parent.mkdir(parents=True, exist_ok=True)
    with closing(_con()) as con:
        con.executescript(SCHEMA)
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
            "INSERT OR REPLACE INTO blocks VALUES (?,?,?,?)",
            (b["id"], b["ts"], b["ip"], b["action"]),
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

def record_device(ip: str, name: Optional[str] = None) -> None:
    now = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    with closing(_con()) as con:
        cur = con.execute("SELECT ip FROM devices WHERE ip=?", (ip,))
        if cur.fetchone() is None:
            con.execute(
                "INSERT INTO devices (ip, first_seen, last_seen, name) VALUES (?, ?, ?, ?)",
                (ip, now, now, name),
            )
        else:
            con.execute("UPDATE devices SET last_seen=? WHERE ip=?", (now, ip))
        con.commit()

def list_devices(limit: int = 200):
    with closing(_con()) as con:
        return [
            dict(r)
            for r in con.execute(
                "SELECT * FROM devices ORDER BY last_seen DESC LIMIT ?", (int(limit),)
            )
        ]

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