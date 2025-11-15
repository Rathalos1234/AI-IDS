"""Unit tests for the Linux firewall helper."""

from __future__ import annotations
from pathlib import Path
from types import SimpleNamespace
import sys
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import firewall

pytestmark = pytest.mark.unit


class _StubResult(SimpleNamespace):
    def __init__(self, returncode: int = 0, stderr: str = "", stdout: str = "") -> None:
        super().__init__(returncode=returncode, stderr=stderr, stdout=stdout)


@pytest.fixture(autouse=True)
def _patch_platform(monkeypatch):
    """Force the helper into a deterministic Linux/root environment."""

    monkeypatch.setattr(firewall, "_supported", lambda: True)
    monkeypatch.setattr(firewall, "_has_privileges", lambda: True)
    monkeypatch.setattr(firewall, "_IPTABLES", "/sbin/iptables")
    yield


def test_ensure_block_bails_when_rule_exists(monkeypatch):
    calls = []

    def _fake_run(cmd, **_):  # noqa: D401 - simple stub
        calls.append(tuple(cmd))
        return _StubResult(returncode=0)

    monkeypatch.setattr(firewall.subprocess, "run", _fake_run)

    ok, err = firewall.ensure_block("192.0.2.15", reason="existing")

    assert ok is True
    assert err is None
    assert calls[0][1] == "-C"


def test_ensure_block_installs_rule_with_comment(monkeypatch):
    seq = iter(
        [
            _StubResult(returncode=1),  # probe for existing rule
            _StubResult(returncode=0),  # insert with comment succeeds
        ]
    )
    calls = []

    def _fake_run(cmd, **_):
        calls.append(tuple(cmd))
        return next(seq)

    monkeypatch.setattr(firewall.subprocess, "run", _fake_run)

    ok, err = firewall.ensure_block("198.51.100.77", reason="auto-high")

    assert ok is True
    assert err is None
    assert any("--comment" in call for call in calls)


def test_ensure_unblock_retries_until_missing(monkeypatch):
    seq = iter(
        [
            _StubResult(returncode=0),  # first delete succeeds
            _StubResult(returncode=1, stderr="no such rule"),  # then stops
        ]
    )
    calls = []

    def _fake_run(cmd, **_):
        calls.append(tuple(cmd))
        return next(seq)

    monkeypatch.setattr(firewall.subprocess, "run", _fake_run)

    ok, err = firewall.ensure_unblock("203.0.113.42")

    assert ok is True
    assert err is None
    assert calls[0][1] == "-D"


def test_ensure_block_reports_unsupported(monkeypatch):
    monkeypatch.setattr(firewall, "_supported", lambda: False)

    ok, err = firewall.ensure_block("203.0.113.8")

    assert ok is False
    assert err == "unsupported_os"


def test_ensure_unblock_requires_root(monkeypatch):
    monkeypatch.setattr(firewall, "_has_privileges", lambda: False)

    ok, err = firewall.ensure_unblock("198.51.100.20")

    assert ok is False
    assert err == "root_required"
