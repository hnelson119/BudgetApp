"""Validate and archive security records outside the application container."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import signal
import socket
import stat
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from types import FrameType
from typing import Any

from core.logging import (
    MAX_SECURITY_LOG_DATAGRAM_BYTES,
    SAFE_BOOLEAN_RECORD_FIELDS,
    SAFE_RECORD_FIELDS,
    redact_text,
)

SOCKET_PATH = Path("/run/security-log/security.sock")
ARCHIVE_DIRECTORY = Path("/var/lib/security-log")
EVENT_FILE = "security-events.jsonl"
ALERT_FILE = "security-alerts.jsonl"
_BASE_FIELDS = {
    "actor_id",
    "environment",
    "household_id",
    "level",
    "logger",
    "message",
    "release",
    "request_id",
    "stream",
    "timestamp",
}
_OPTIONAL_FIELDS = {*SAFE_RECORD_FIELDS, *SAFE_BOOLEAN_RECORD_FIELDS, "exception_type", "traceback"}
_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_EVENT_ID = re.compile(r"^[a-z][a-z0-9_]*(?:[._][a-z0-9_]+)+$")
_stop_requested = False


class CollectorFailure(RuntimeError):
    pass


def _current_uid() -> int:
    getuid = getattr(os, "getuid", None)
    if getuid is None:
        raise CollectorFailure("Linux ownership checks are unavailable.")
    return int(getuid())


def _fixed_diagnostic(event: str, level: str, message: str) -> None:
    record = {
        "timestamp": datetime.now(tz=UTC).isoformat(timespec="milliseconds"),
        "level": level,
        "logger": "security.archive",
        "stream": "operational",
        "event": event,
        "message": message,
    }
    print(json.dumps(record, separators=(",", ":")), file=sys.stderr, flush=True)


def _clean_string(value: Any, *, field: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise CollectorFailure(f"Security-log field {field!r} is invalid.")
    cleaned = redact_text(value)
    try:
        cleaned.encode("utf-8")
    except UnicodeEncodeError as error:
        raise CollectorFailure(f"Security-log field {field!r} is not valid UTF-8.") from error
    return cleaned


def _parse_utc_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise CollectorFailure("A security-log record has an invalid timestamp.")
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError as error:
        raise CollectorFailure("A security-log record has an invalid timestamp.") from error
    if timestamp.tzinfo is None or timestamp.utcoffset() != UTC.utcoffset(timestamp):
        raise CollectorFailure("A security-log timestamp is not UTC.")
    return timestamp


def validate_record(payload: bytes) -> dict[str, Any]:
    if not payload or len(payload) > MAX_SECURITY_LOG_DATAGRAM_BYTES:
        raise CollectorFailure("A security-log datagram is outside the size limit.")
    try:
        raw = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise CollectorFailure("A security-log datagram is not valid UTF-8 JSON.") from error
    if not isinstance(raw, dict) or not _BASE_FIELDS <= set(raw):
        raise CollectorFailure("A security-log record is structurally incomplete.")
    if set(raw) - _BASE_FIELDS - _OPTIONAL_FIELDS:
        raise CollectorFailure("A security-log record contains an unapproved field.")
    if raw.get("stream") != "security" or raw.get("level") not in _LEVELS:
        raise CollectorFailure("A security-log record has an invalid stream or level.")
    logger_name = raw.get("logger")
    if not isinstance(logger_name, str) or not (
        logger_name == "security" or logger_name.startswith("django.security")
    ):
        raise CollectorFailure("A security-log record has an unapproved logger.")
    _parse_utc_timestamp(raw["timestamp"])

    cleaned: dict[str, Any] = {}
    for field in _BASE_FIELDS:
        maximum = 2048 if field == "message" else 512
        cleaned[field] = _clean_string(raw[field], field=field, maximum=maximum)
    for field in SAFE_RECORD_FIELDS:
        if field not in raw:
            continue
        value = raw[field]
        if field == "event":
            value = _clean_string(value, field=field)
            if _EVENT_ID.fullmatch(value) is None:
                raise CollectorFailure("A security-log event identifier is invalid.")
        elif isinstance(value, str):
            value = _clean_string(value, field=field)
        elif (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or (isinstance(value, float) and not math.isfinite(value))
        ):
            raise CollectorFailure(f"Security-log field {field!r} has an invalid type.")
        cleaned[field] = value
    for field in SAFE_BOOLEAN_RECORD_FIELDS:
        if field in raw:
            if type(raw[field]) is not bool:
                raise CollectorFailure(f"Security-log field {field!r} has an invalid type.")
            cleaned[field] = raw[field]
    if "exception_type" in raw:
        cleaned["exception_type"] = _clean_string(raw["exception_type"], field="exception_type")
    if "traceback" in raw:
        frames = raw["traceback"]
        if not isinstance(frames, list) or len(frames) > 32:
            raise CollectorFailure("A security-log traceback is invalid.")
        cleaned["traceback"] = [
            {
                "file": _clean_string(frame.get("file"), field="traceback.file"),
                "line": frame.get("line"),
                "function": _clean_string(frame.get("function"), field="traceback.function"),
            }
            for frame in frames
            if isinstance(frame, dict)
            and set(frame) == {"file", "line", "function"}
            and isinstance(frame.get("line"), int)
            and frame["line"] > 0
        ]
        if len(cleaned["traceback"]) != len(frames):
            raise CollectorFailure("A security-log traceback frame is invalid.")
    return cleaned


def _open_append_only(path: Path) -> int:
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    status = os.fstat(descriptor)
    if not stat.S_ISREG(status.st_mode) or (os.name != "nt" and status.st_uid != _current_uid()):
        os.close(descriptor)
        raise CollectorFailure("A security-log archive target is not an owned regular file.")
    if os.name != "nt":
        fchmod = getattr(os, "fchmod", None)
        if fchmod is None:
            os.close(descriptor)
            raise CollectorFailure("Linux file-mode enforcement is unavailable.")
        fchmod(descriptor, 0o600)
    return descriptor


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("The security-log archive write did not make progress.")
        remaining = remaining[written:]


def archive_record(record: dict[str, Any], directory: Path) -> bool:
    serialized = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
    descriptor = _open_append_only(directory / EVENT_FILE)
    try:
        _write_all(descriptor, serialized.encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

    is_alert = record["level"] in {"WARNING", "ERROR", "CRITICAL"}
    if is_alert:
        alert = {
            "timestamp": record["timestamp"],
            "level": record["level"],
            "event": record.get("event", "security.framework.warning"),
            "request_id": record["request_id"],
            "release": record["release"],
        }
        descriptor = _open_append_only(directory / ALERT_FILE)
        try:
            _write_all(
                descriptor,
                (json.dumps(alert, separators=(",", ":")) + "\n").encode("utf-8"),
            )
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return is_alert


def _validate_directory(path: Path, *, expected_mode: int) -> None:
    if path.is_symlink() or not path.is_dir():
        raise CollectorFailure("A security-log directory is not a real directory.")
    status = path.stat()
    if os.name != "nt" and (
        status.st_uid != _current_uid() or stat.S_IMODE(status.st_mode) != expected_mode
    ):
        raise CollectorFailure("A security-log directory has unsafe ownership or permissions.")


def _request_stop(_signal: int, _frame: FrameType | None) -> None:
    global _stop_requested
    _stop_requested = True


def serve(socket_path: Path = SOCKET_PATH, archive_directory: Path = ARCHIVE_DIRECTORY) -> None:
    global _stop_requested
    _stop_requested = False
    _validate_directory(socket_path.parent, expected_mode=0o711)
    _validate_directory(archive_directory, expected_mode=0o700)
    if socket_path.exists() or socket_path.is_symlink():
        status = socket_path.lstat()
        if not stat.S_ISSOCK(status.st_mode) or status.st_uid != _current_uid():
            raise CollectorFailure("The security-log socket path is unsafe.")
        socket_path.unlink()

    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)
    unix_family = getattr(socket, "AF_UNIX", None)
    if unix_family is None:
        raise CollectorFailure("Unix sockets are unavailable.")
    with socket.socket(unix_family, socket.SOCK_DGRAM) as receiver:
        receiver.bind(str(socket_path))
        socket_path.chmod(0o622)
        receiver.settimeout(1)
        _fixed_diagnostic("security.archive.ready", "INFO", "Security-log archive is ready.")
        try:
            while not _stop_requested:
                try:
                    payload = receiver.recv(MAX_SECURITY_LOG_DATAGRAM_BYTES + 1)
                    record = validate_record(payload)
                    if archive_record(record, archive_directory):
                        _fixed_diagnostic(
                            "security.archive.alert_recorded",
                            "WARNING",
                            "A security alert is ready for operator review.",
                        )
                except TimeoutError:
                    continue
                except (CollectorFailure, OSError):
                    _fixed_diagnostic(
                        "security.archive.record_rejected",
                        "ERROR",
                        "A security-log record was rejected safely.",
                    )
        finally:
            if socket_path.exists() and stat.S_ISSOCK(socket_path.lstat().st_mode):
                socket_path.unlink()


def healthcheck(
    socket_path: Path = SOCKET_PATH, archive_directory: Path = ARCHIVE_DIRECTORY
) -> int:
    try:
        _validate_directory(socket_path.parent, expected_mode=0o711)
        _validate_directory(archive_directory, expected_mode=0o700)
        socket_status = socket_path.lstat()
        if not stat.S_ISSOCK(socket_status.st_mode) or (
            os.name != "nt"
            and (
                socket_status.st_uid != _current_uid()
                or stat.S_IMODE(socket_status.st_mode) != 0o622
            )
        ):
            return 1
    except (CollectorFailure, OSError):
        return 1
    return 0


def review_alerts(archive_directory: Path = ARCHIVE_DIRECTORY) -> dict[str, Any]:
    _validate_directory(archive_directory, expected_mode=0o700)
    path = archive_directory / ALERT_FILE
    if not path.exists():
        return {"alert_count": 0, "by_level": {}, "by_event": {}}
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
        raise CollectorFailure("The security alert archive is unsafe or unexpectedly large.")
    levels: Counter[str] = Counter()
    events: Counter[str] = Counter()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise CollectorFailure("The security alert archive could not be read.") from error
    for line in lines:
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise CollectorFailure("The security alert archive contains invalid JSON.") from error
        if not isinstance(record, dict) or set(record) != {
            "event",
            "level",
            "release",
            "request_id",
            "timestamp",
        }:
            raise CollectorFailure("The security alert archive contains an invalid record.")
        level = record.get("level")
        event = record.get("event")
        if (
            level not in {"WARNING", "ERROR", "CRITICAL"}
            or not isinstance(event, str)
            or _EVENT_ID.fullmatch(event) is None
        ):
            raise CollectorFailure("The security alert archive contains invalid alert metadata.")
        _parse_utc_timestamp(record["timestamp"])
        _clean_string(record["release"], field="release")
        _clean_string(record["request_id"], field="request_id")
        levels[level] += 1
        events[event] += 1
    return {
        "alert_count": len(lines),
        "by_level": dict(sorted(levels.items())),
        "by_event": dict(sorted(events.items())),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode", choices=("serve", "healthcheck", "review"), nargs="?", default="serve"
    )
    arguments = parser.parse_args()
    if arguments.mode == "healthcheck":
        return healthcheck()
    if arguments.mode == "review":
        try:
            print(json.dumps(review_alerts(), separators=(",", ":")))
        except (CollectorFailure, OSError):
            _fixed_diagnostic(
                "security.archive.review_failed",
                "ERROR",
                "Security alert review failed safely.",
            )
            return 1
        return 0
    try:
        serve()
    except (CollectorFailure, OSError):
        _fixed_diagnostic(
            "security.archive.startup_failed",
            "CRITICAL",
            "Security-log archive startup failed safely.",
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
