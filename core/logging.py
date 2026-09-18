"""Structured logging with request context and defensive redaction."""

import json
import logging
import os
import re
import socket
import sys
import traceback
from contextvars import ContextVar, Token
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_request_id: ContextVar[str] = ContextVar("request_id", default="-")
_actor_id: ContextVar[str] = ContextVar("actor_id", default="-")
_household_id: ContextVar[str] = ContextVar("household_id", default="-")

_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|secret|token|authorization|cookie|sessionid|csrf(?:middleware)?token|"
    r"api[_-]?key|amount|balance|income|expense)\b(\s*[:=]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^,;\r\n]+)"
)
_BEARER_TOKEN = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]+")
_EMAIL_ADDRESS = re.compile(r"(?i)\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
_LONG_NUMBER = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")

SAFE_RECORD_FIELDS = (
    "event",
    "method",
    "route",
    "status_code",
    "duration_ms",
    "job_id",
    "import_id",
    "error_reference",
    "check_name",
    "result",
)
SAFE_BOOLEAN_RECORD_FIELDS = ("accepted", "rate_limited")
MAX_SECURITY_LOG_DATAGRAM_BYTES = 32 * 1024


def redact_text(value: object) -> str:
    """Redact common credential and financial patterns from untrusted text."""

    text = str(value)
    text = _SENSITIVE_ASSIGNMENT.sub(r"\1\2[REDACTED]", text)
    text = _BEARER_TOKEN.sub("Bearer [REDACTED]", text)
    text = _EMAIL_ADDRESS.sub("[REDACTED_EMAIL]", text)
    return _LONG_NUMBER.sub("[REDACTED_NUMBER]", text)


def bind_request_context(request_id: str) -> Token[str]:
    return _request_id.set(request_id)


def bind_actor_context(
    *, actor_id: str = "-", household_id: str = "-"
) -> tuple[Token[str], Token[str]]:
    return _actor_id.set(actor_id), _household_id.set(household_id)


def reset_request_context(token: Token[str]) -> None:
    _request_id.reset(token)


def reset_actor_context(tokens: tuple[Token[str], Token[str]]) -> None:
    actor_token, household_token = tokens
    _actor_id.reset(actor_token)
    _household_id.reset(household_token)


def current_request_id() -> str:
    return _request_id.get()


class RequestContextFilter(logging.Filter):
    """Attach safe correlation identifiers to every emitted record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.__dict__["request_id"] = _request_id.get()
        record.__dict__["actor_id"] = _actor_id.get()
        record.__dict__["household_id"] = _household_id.get()
        return True


class SecurityStreamFilter(logging.Filter):
    """Mark security records for independent routing and retention."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.__dict__["stream"] = "security"
        return True


class UnixDatagramJsonHandler(logging.Handler):
    """Send one already-redacted JSON record to the isolated archive collector."""

    def __init__(self, socket_path: str) -> None:
        super().__init__()
        if not socket_path.startswith("/") or "\x00" in socket_path:
            raise ValueError("The security-log socket path must be an absolute Linux path.")
        self.socket_path = socket_path

    def emit(self, record: logging.LogRecord) -> None:
        try:
            payload = self.format(record).encode("utf-8")
            if not payload or len(payload) > MAX_SECURITY_LOG_DATAGRAM_BYTES:
                raise ValueError("The security-log record is outside the bounded datagram size.")
            unix_family = getattr(socket, "AF_UNIX", None)
            if unix_family is None:
                raise OSError("Unix sockets are unavailable.")
            with socket.socket(unix_family, socket.SOCK_DGRAM) as transport:
                transport.settimeout(0.25)
                transport.sendto(payload, self.socket_path)
        except (OSError, UnicodeError, ValueError):
            fallback = {
                "timestamp": datetime.now(tz=UTC).isoformat(timespec="milliseconds"),
                "level": "ERROR",
                "logger": "security.archive",
                "stream": "security",
                "environment": os.getenv("APP_ENVIRONMENT", "development"),
                "release": os.getenv("APP_RELEASE", "development"),
                "request_id": "-",
                "actor_id": "-",
                "household_id": "-",
                "message": "Security-log delivery failed.",
                "event": "security.archive.delivery_failed",
            }
            sys.stderr.write(json.dumps(fallback, separators=(",", ":")) + "\n")
            sys.stderr.flush()


class RedactingJsonFormatter(logging.Formatter):
    """Emit an allowlisted JSON record and redact all free-form text."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(
                timespec="milliseconds"
            ),
            "level": record.levelname,
            "logger": record.name,
            "stream": getattr(record, "stream", "operational"),
            "environment": os.getenv("APP_ENVIRONMENT", "development"),
            "release": os.getenv("APP_RELEASE", "development"),
            "request_id": getattr(record, "request_id", "-"),
            "actor_id": getattr(record, "actor_id", "-"),
            "household_id": getattr(record, "household_id", "-"),
            "message": redact_text(record.getMessage()),
        }

        for field in SAFE_RECORD_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = redact_text(value) if isinstance(value, str) else value

        for field in SAFE_BOOLEAN_RECORD_FIELDS:
            value = getattr(record, field, None)
            if type(value) is bool:
                payload[field] = value

        if record.exc_info:
            exception_type, _, exception_traceback = record.exc_info
            if exception_type is not None:
                payload["exception_type"] = (
                    f"{exception_type.__module__}.{exception_type.__qualname__}"
                )
            if exception_traceback is not None:
                payload["traceback"] = [
                    {
                        "file": Path(frame.filename).name,
                        "line": frame.lineno,
                        "function": frame.name,
                    }
                    for frame in traceback.extract_tb(exception_traceback)
                ]

        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)
