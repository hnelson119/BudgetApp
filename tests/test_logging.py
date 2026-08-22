import json
import logging
import re
import sys

import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse

from core.logging import (
    RedactingJsonFormatter,
    RequestContextFilter,
    SecurityStreamFilter,
    bind_actor_context,
    bind_request_context,
    reset_actor_context,
    reset_request_context,
)

TEST_PASSWORD = "safe-test-pass"  # pragma: allowlist secret


def test_json_formatter_redacts_sensitive_values() -> None:
    message = (
        "password=visible-secret, authorization=Bearer abc.def.ghi; "
        "email person@example.com card 4111 1111 1111 1111"
    )
    record = logging.LogRecord("test", logging.ERROR, __file__, 1, message, (), None)

    payload = json.loads(RedactingJsonFormatter().format(record))
    serialized = json.dumps(payload)

    assert payload["message"].startswith("password=[REDACTED]")
    assert "visible-secret" not in serialized
    assert "abc.def.ghi" not in serialized
    assert "person@example.com" not in serialized
    assert "4111" not in serialized


def test_json_formatter_omits_untrusted_exception_message() -> None:
    try:
        raise RuntimeError("private merchant description and $123.45")
    except RuntimeError:
        record = logging.LogRecord(
            "test", logging.ERROR, __file__, 1, "Safe summary.", (), sys.exc_info()
        )

    payload = json.loads(RedactingJsonFormatter().format(record))
    serialized = json.dumps(payload)

    assert payload["exception_type"] == "builtins.RuntimeError"
    assert any(
        frame["function"] == "test_json_formatter_omits_untrusted_exception_message"
        for frame in payload["traceback"]
    )
    assert "private merchant" not in serialized
    assert "$123.45" not in serialized


def test_context_filter_adds_pseudonymous_ids_and_resets_them() -> None:
    request_token = bind_request_context("request-12345678")
    actor_tokens = bind_actor_context(
        actor_id="11111111-1111-1111-1111-111111111111",
        household_id="22222222-2222-2222-2222-222222222222",
    )
    try:
        record = logging.LogRecord("test", logging.INFO, __file__, 1, "ok", (), None)
        RequestContextFilter().filter(record)
        assert record.request_id == "request-12345678"  # type: ignore[attr-defined]
        assert record.actor_id == "11111111-1111-1111-1111-111111111111"  # type: ignore[attr-defined]
        assert record.household_id == (  # type: ignore[attr-defined]
            "22222222-2222-2222-2222-222222222222"
        )
    finally:
        reset_actor_context(actor_tokens)
        reset_request_context(request_token)


def test_security_filter_marks_security_stream() -> None:
    record = logging.LogRecord("security", logging.WARNING, __file__, 1, "event", (), None)

    SecurityStreamFilter().filter(record)

    assert record.stream == "security"  # type: ignore[attr-defined]


def test_valid_request_id_is_returned_to_client(client: Client) -> None:
    response = client.get(reverse("core:home"), headers={"X-Request-ID": "request-12345678"})

    assert response.headers["X-Request-ID"] == "request-12345678"
    assert response.headers["Content-Security-Policy"].startswith("default-src 'self'")
    assert response.headers["Permissions-Policy"] == "camera=(), microphone=(), geolocation=()"


def test_untrusted_request_id_is_replaced(client: Client) -> None:
    response = client.get(reverse("core:home"), headers={"X-Request-ID": "bad\nvalue"})

    request_id = response.headers["X-Request-ID"]
    assert request_id != "bad\nvalue"
    assert re.fullmatch(r"[0-9a-f]{32}", request_id)


def test_not_found_page_has_safe_reference(client: Client) -> None:
    response = client.get("/does-not-exist")

    request_id = response.headers["X-Request-ID"]
    assert response.status_code == 404
    assert request_id.encode() in response.content
    assert b"Page not found" in response.content


def test_unhandled_error_hides_sensitive_details(client: Client) -> None:
    client.raise_request_exception = False

    response = client.get("/_test/error/")

    assert response.status_code == 500
    assert response.headers["X-Request-ID"].encode() in response.content
    assert b"not-real-secret" not in response.content
    assert b"Something went wrong" in response.content


@pytest.mark.django_db
def test_authenticated_responses_cannot_be_cached(client: Client) -> None:
    user = get_user_model().objects.create_user(email="person@example.com", password=TEST_PASSWORD)
    client.force_login(user)

    response = client.get(reverse("core:home"))

    assert response.headers["Cache-Control"] == "no-store, private"
    assert response.headers["Pragma"] == "no-cache"
