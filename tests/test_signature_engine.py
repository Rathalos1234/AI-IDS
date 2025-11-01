import pandas as pd

from signature_engine import Rule, SignatureEngine, default_engine


def test_default_engine_flags_port_scans():
    engine = default_engine()
    last_row = {"unique_dports_15s": 12, "direction": 1, "dport": 80}

    hits = engine.evaluate(last_row, pd.DataFrame([last_row]))

    assert {h.name for h in hits} == {"port-scan-suspected"}
    assert all(h.severity == "high" for h in hits)


def test_default_engine_flags_sensitive_inbound_port():
    engine = default_engine()
    last_row = {"direction": 0, "dport": 22, "unique_dports_15s": 1}

    hits = engine.evaluate(last_row, pd.DataFrame([last_row]))

    assert any(h.name == "inbound-sensitive-port" for h in hits)
    assert any(h.severity == "medium" for h in hits)


def test_engine_ignores_rule_errors():
    def boom(last_row, window_df):
        raise RuntimeError("rule failed")

    flaky_rule = Rule(
        name="flaky",
        severity="low",
        description="intermittent failure",
        match=boom,
    )
    engine = SignatureEngine([flaky_rule])

    hits = engine.evaluate({}, pd.DataFrame())

    assert hits == []
