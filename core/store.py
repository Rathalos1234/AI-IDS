import os
from datetime import datetime
from typing import List, Dict
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///ids.db")
engine = create_engine(DATABASE_URL, future=True)
SessionLocal = sessionmaker(bind=engine, future=True)

#2 tables alert and blocks
def init_db():
    with engine.begin() as conn:
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS alerts(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts TEXT NOT NULL,
          src_ip TEXT NOT NULL,
          label TEXT NOT NULL,
          severity TEXT NOT NULL,
          kind TEXT NOT NULL,
          details TEXT
        );
        """))
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS blocks(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts TEXT NOT NULL,
          ip TEXT NOT NULL,
          action TEXT NOT NULL
        );
        """))

def save_alert(a: Dict):
    with engine.begin() as conn:
        conn.execute(text("""
        INSERT INTO alerts(ts, src_ip, label, severity, kind, details)
        VALUES (:ts, :src_ip, :label, :severity, :kind, :details)
        """), a)

def list_alerts(limit: int = 100) -> List[Dict]:
    with engine.begin() as conn:
        rows = conn.execute(text("""
        SELECT id, ts, src_ip, label, severity, kind, details
        FROM alerts ORDER BY id DESC LIMIT :limit
        """), {"limit": limit}).mappings().all()
        return [dict(r) for r in rows]

def block_ip(ip: str):
    with engine.begin() as conn:
        conn.execute(text("""
        INSERT INTO blocks(ts, ip, action) VALUES (:ts, :ip, 'BLOCK')
        """), {"ts": datetime.utcnow().isoformat(), "ip": ip})

def unblock_ip(ip: str):
    with engine.begin() as conn:
        conn.execute(text("""
        INSERT INTO blocks(ts, ip, action) VALUES (:ts, :ip, 'UNBLOCK')
        """), {"ts": datetime.utcnow().isoformat(), "ip": ip})

def list_blocks(limit: int = 100) -> List[Dict]:
    with engine.begin() as conn:
        rows = conn.execute(text("""
        SELECT id, ts, ip, action FROM blocks
        ORDER BY id DESC LIMIT :limit
        """), {"limit": limit}).mappings().all()
        return [dict(r) for r in rows]
