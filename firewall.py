"""Linux firewall helpers for runtime blocking."""

from __future__ import annotations
import ipaddress
import logging
import os
import platform
import shutil
import subprocess
import threading
from typing import Tuple, Optional

_LOG = logging.getLogger("ids.firewall")
_CHAIN = os.environ.get("IDS_FIREWALL_CHAIN", "INPUT")
_RULE_TARGET = os.environ.get("IDS_FIREWALL_TARGET", "DROP")
_TAG = os.environ.get("IDS_FIREWALL_TAG", "IDS_AUTOBLOCK")
_LOCK = threading.Lock()

_IPTABLES = shutil.which("iptables")


def _supported() -> bool:
    return platform.system().lower() == "linux"


def _has_privileges() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def ensure_block(ip: str, reason: str | None = None) -> Tuple[bool, str | None]:
    """Ensure an INPUT rule drops traffic from ``ip``."""

    if not _supported():
        return False, "unsupported_os"
    if not _IPTABLES:
        return False, "iptables_missing"
    if not _has_privileges():
        return False, "root_required"

    with _LOCK:
        check = subprocess.run(
            [_IPTABLES, "-C", _CHAIN, "-s", ip, "-j", _RULE_TARGET],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if check.returncode == 0:
            return True, None

        base_cmd = [_IPTABLES, "-I", _CHAIN, "1", "-s", ip, "-j", _RULE_TARGET]
        if reason:
            annotated = base_cmd + [
                "-m",
                "comment",
                "--comment",
                f"{_TAG}:{reason[:32]}".strip(":"),
            ]
            added = subprocess.run(
                annotated,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if added.returncode == 0:
                _LOG.info("Firewall block installed for %s", ip)
                return True, None
            _LOG.debug("iptables comment failed for %s: %s", ip, added.stderr.strip())

        added = subprocess.run(
            base_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if added.returncode == 0:
            _LOG.info("Firewall block installed for %s", ip)
            return True, None

        error = (
            (added.stderr or "iptables_failed").strip() if added else "iptables_failed"
        )
        _LOG.error("Firewall block failed for %s: %s", ip, error)
        return False, error or "iptables_failed"


def ensure_unblock(ip: str) -> Tuple[bool, str | None]:
    """Remove any INPUT drop rules for ``ip``."""

    if not _supported():
        return False, "unsupported_os"
    if not _IPTABLES:
        return False, "iptables_missing"
    if not _has_privileges():
        return False, "root_required"

    success = False
    last_error: str | None = None
    with _LOCK:
        while True:
            res = subprocess.run(
                [_IPTABLES, "-D", _CHAIN, "-s", ip, "-j", _RULE_TARGET],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if res.returncode == 0:
                success = True
                continue
            if success:
                break
            last_error = (res.stderr or "iptables_failed").strip() or None
            break
    if success:
        _LOG.info("Firewall unblock applied for %s", ip)
        return True, None
    if last_error:
        _LOG.error("Firewall unblock failed for %s: %s", ip, last_error)
    return False, last_error or "iptables_failed"


def capabilities() -> dict:
    """Expose capability flags for API responses."""

    return {
        "supported": _supported(),
        "iptables": bool(_IPTABLES),
        "requires_root": True,
    }


class Firewall:
    """High level firewall interface with input validation."""

    def __init__(self) -> None:
        self._lock = _LOCK

    @staticmethod
    def _validate_ip(ip: str) -> str:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ValueError("Invalid IP address") from exc
        return str(addr)

    def apply(
        self, ip: str, *, action: str = "block", reason: Optional[str] = None
    ) -> bool:
        clean_ip = self._validate_ip(ip)
        action = (action or "block").lower()
        if action == "block":
            success, error = ensure_block(clean_ip, reason)
        elif action == "unblock":
            success, error = ensure_unblock(clean_ip)
        else:
            raise ValueError("Unsupported firewall action")
        if not success and error:
            raise RuntimeError(error)
        return success

    def remove(self, ip: str) -> bool:
        return self.apply(ip, action="unblock")
