import sqlite3
from contextlib import closing
from pathlib import Path

DB = Path("ids_web.db")
SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY, ts TEXT, src_ip TEXT, label TEXT, severity TEXT, kind TEXT
);
CREATE TABLE IF NOT EXISTS blocks (
  id TEXT PRIMARY KEY, ts TEXT, ip TEXT, action TEXT
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

def list_alerts(limit=100):
    with closing(_con()) as con:
        return [dict(r) for r in con.execute(
            "SELECT * FROM alerts ORDER BY ts DESC LIMIT ?",
            (limit,)
        )]

def list_blocks(limit=100):
    with closing(_con()) as con:
        return [dict(r) for r in con.execute(
            "SELECT * FROM blocks ORDER BY ts DESC LIMIT ?",
            (limit,)
        )]

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
        con.execute("INSERT OR REPLACE INTO alerts VALUES (?,?,?,?,?,?)",
                    (a["id"],a["ts"],a["src_ip"],a["label"],a["severity"],a["kind"]))
        con.commit()

def insert_block(b):
    with closing(_con()) as con:
        con.execute("INSERT OR REPLACE INTO blocks VALUES (?,?,?,?)",
                    (b["id"],b["ts"],b["ip"],b["action"]))
        con.commit()
