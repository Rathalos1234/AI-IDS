from pydantic import BaseModel
from typing import Literal, Dict, Optional
from datetime import datetime

class FreatureExp(BaseModel):
    ts: datetime
    window_secs: int = 5
    src_ip: str
    dst_ip: Optional[str] = None
    pkts: int
    bytes: int
    uniq_dsts: int
    uniq_dst_ports: int
    syn_rate: int = 0
    rst_rate: int = 0
    failed_auth_rate: int = 0
    avg_len: float = 0.0

class Detection(BaseModel):
    ts: datetime
    src_ip: str
    kind: Literal["signature","anomaly"]
    label: str
    score: float = 1.0
    severity: Literal["low","medium","high"] = "low"
    details: Dict[str, str] = {}
