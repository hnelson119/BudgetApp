import json
import logging
import math
from pathlib import Path
from typing import Any

import pytest

from core.logging import RedactingJsonFormatter, SecurityStreamFilter, UnixDatagramJsonHandler
from core.security_log_collector import (
    ALERT_FILE,
    EVENT_FILE,
    CollectorFailure,
    archive_record,
    review_alerts,
    validate_record,
)


def _security_payload(**overrides: Any) -> bytes:
    record = {
        "timestamp": "2026-09-05T12:00:00.000+00:00",
        "level": "WARNING",
        "logger": "security",
        "stream": "security",
        "environment": "production",
        "release": "candidate",
        "request_id": "request-12345678",
        "actor_id": "actor-12345678",
        "household_id": "household-12345678",
        "message": "Rejected password=visible-value",
        "event": "auth.login.failed",
    }
    record.update(overrides)
    return json.dumps(record).encode("utf-8")


def test_collector_validates_and_redacts_security_records() -> None:
    record = validate_record(_security_payload())

    assert record["stream"] == "security"
    assert record["event"] == "auth.login.failed"
    assert "visible-value" not in record["message"]


@pytest.mark.parametrize(
    "overrides",
    (
        {"stream": "operational"},
        {"logger": "budget.request"},
        {"timestamp": "2026-09-05T12:00:00"},
        {"event": "not valid"},
        {"unapproved": "field"},
        {"duration_ms": math.inf},
    ),
)
def test_collector_rejects_unapproved_records(overrides: dict[str, str]) -> None:
    with pytest.raises(CollectorFailure):
        validate_record(_security_payload(**overrides))


def test_collector_archives_events_and_warning_alerts(tmp_path: Path) -> None:
    record = validate_record(_security_payload())

    assert archive_record(record, tmp_path) is True

    archived = json.loads((tmp_path / EVENT_FILE).read_text(encoding="utf-8"))
    alert = json.loads((tmp_path / ALERT_FILE).read_text(encoding="utf-8"))
    assert archived["event"] == "auth.login.failed"
    assert alert == {
        "timestamp": record["timestamp"],
        "level": "WARNING",
        "event": "auth.login.failed",
        "request_id": "request-12345678",
        "release": "candidate",
    }
    assert review_alerts(tmp_path) == {
        "alert_count": 1,
        "by_level": {"WARNING": 1},
        "by_event": {"auth.login.failed": 1},
    }


def test_alert_review_rejects_invalid_metadata(tmp_path: Path) -> None:
    (tmp_path / ALERT_FILE).write_text(
        json.dumps(
            {
                "timestamp": "not-a-timestamp",
                "level": "WARNING",
                "event": "auth.login.failed",
                "request_id": "request-12345678",
                "release": "candidate",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(CollectorFailure):
        review_alerts(tmp_path)


def test_unix_datagram_handler_sends_only_formatted_json(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[tuple[bytes, str]] = []

    class FakeSocket:
        def __enter__(self) -> "FakeSocket":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def settimeout(self, _timeout: float) -> None:
            return None

        def sendto(self, payload: bytes, path: str) -> None:
            sent.append((payload, path))

    monkeypatch.setattr("core.logging.socket.socket", lambda *_args: FakeSocket())
    monkeypatch.setattr("core.logging.socket.AF_UNIX", 1, raising=False)
    handler = UnixDatagramJsonHandler("/run/security-log/security.sock")
    handler.setFormatter(RedactingJsonFormatter())
    handler.addFilter(SecurityStreamFilter())
    record = logging.LogRecord(
        "security", logging.WARNING, __file__, 1, "password=visible-value", (), None
    )

    handler.handle(record)

    payload, path = sent[0]
    assert path == "/run/security-log/security.sock"
    assert json.loads(payload)["stream"] == "security"
    assert b"visible-value" not in payload


def test_unix_datagram_handler_reports_delivery_failure_without_record(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "core.logging.socket.socket", lambda *_args: (_ for _ in ()).throw(OSError("secret"))
    )
    handler = UnixDatagramJsonHandler("/run/security-log/security.sock")
    handler.setFormatter(RedactingJsonFormatter())
    record = logging.LogRecord(
        "security", logging.ERROR, __file__, 1, "password=visible-value", (), None
    )

    handler.handle(record)

    output = capsys.readouterr().err
    assert "security.archive.delivery_failed" in output
    assert "visible-value" not in output
    assert "secret" not in output
