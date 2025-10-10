# -*- coding: utf-8 -*-
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Dict, List
import pandas as pd  # already in requirements


@dataclass
class SigResult:
    name: str
    severity: str
    description: str


@dataclass
class Rule:
    name: str
    severity: str
    description: str
    match: Callable[[Dict, pd.DataFrame], bool]  # (last_row, window_df) -> bool


class SignatureEngine:
    def __init__(self, rules: List[Rule]) -> None:
        self.rules = list(rules)

    def evaluate(self, last_row: Dict, window_df: pd.DataFrame) -> List[SigResult]:
        hits: List[SigResult] = []
        for r in self.rules:
            try:
                if r.match(last_row, window_df):
                    hits.append(SigResult(r.name, r.severity, r.description))
            except Exception:
                # never fail the pipeline
                continue
        return hits


# --- Simple default rules ---
def _rule_port_scan(last_row: Dict, window_df: pd.DataFrame) -> bool:
    return float(last_row.get("unique_dports_15s", 0.0)) >= 10.0


_SENSITIVE = {22, 23, 2323, 3389, 5900}


def _rule_inbound_sensitive_port(last_row: Dict, window_df: pd.DataFrame) -> bool:
    return (
        int(last_row.get("direction", 0)) == 0
        and int(last_row.get("dport", 0)) in _SENSITIVE
    )


def default_engine() -> SignatureEngine:
    return SignatureEngine(
        [
            Rule(
                "port-scan-suspected",
                "high",
                "Source contacted many unique destination ports over a short window.",
                _rule_port_scan,
            ),
            Rule(
                "inbound-sensitive-port",
                "medium",
                "Inbound traffic to a sensitive service port.",
                _rule_inbound_sensitive_port,
            ),
        ]
    )
