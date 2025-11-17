"""
Minimal JWT (HS256) helper used for unit tests.

This module implements a tiny subset of PyJWT that our tests use.
It supports HS256 tokens with an ``exp`` claim and provides the
``encode``/``decode`` helpers plus the ``ExpiredSignatureError`` and
``InvalidTokenError`` exceptions.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable


class InvalidTokenError(Exception):
    """Raised when a token cannot be decoded."""


class ExpiredSignatureError(InvalidTokenError):
    """Raised when the ``exp`` claim is in the past."""


def _b64encode(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _b64decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _coerce_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    coerced: Dict[str, Any] = {}
    for key, value in payload.items():
        if isinstance(value, datetime):
            coerced[key] = int(value.timestamp())
        else:
            coerced[key] = value
    return coerced


def encode(payload: Dict[str, Any], key: str, algorithm: str = "HS256") -> str:
    if algorithm.upper() != "HS256":
        raise NotImplementedError("Only HS256 is supported in the test shim")
    header = {"alg": "HS256", "typ": "JWT"}
    body = _coerce_payload(dict(payload))
    segments = [
        _b64encode(json.dumps(header, separators=(",", ":")).encode("utf-8")),
        _b64encode(json.dumps(body, separators=(",", ":")).encode("utf-8")),
    ]
    signing_input = b".".join(segments)
    signature = hmac.new(key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    segments.append(_b64encode(signature))
    return ".".join(segment.decode("ascii") for segment in segments)


def decode(
    token: str, key: str, algorithms: Iterable[str] | None = None
) -> Dict[str, Any]:
    algorithms = list(algorithms or ["HS256"])
    if "HS256" not in {alg.upper() for alg in algorithms}:
        raise InvalidTokenError("Unsupported algorithm")

    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError as exc:
        raise InvalidTokenError("Token structure invalid") from exc

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected_sig = hmac.new(key.encode("utf-8"), signing_input, hashlib.sha256).digest()
    actual_sig = _b64decode(signature_b64)
    if not hmac.compare_digest(expected_sig, actual_sig):
        raise InvalidTokenError("Signature verification failed")

    payload_bytes = _b64decode(payload_b64)
    payload = json.loads(payload_bytes.decode("utf-8"))

    exp = payload.get("exp")
    if exp is not None:
        if isinstance(exp, str):
            try:
                exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
            except ValueError as exc:
                raise InvalidTokenError("Invalid exp claim") from exc
        else:
            exp_dt = datetime.fromtimestamp(float(exp), tz=timezone.utc)
        if exp_dt <= datetime.now(timezone.utc):
            raise ExpiredSignatureError("Token has expired")
        payload["exp"] = exp_dt

    return payload
