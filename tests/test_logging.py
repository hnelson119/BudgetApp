import json
import logging
import re
import sys

import pytest
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.test import Client, RequestFactory, override_settings
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
from core.middleware import (
    HostBoundaryMiddleware,
    NonBrowserTransportBoundaryMiddleware,
    OperationalEndpointBoundaryMiddleware,
    ProxyBoundaryMiddleware,
    SameOriginResponseBoundaryMiddleware,
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


def test_same_origin_boundary_removes_every_cors_permission() -> None:
    cors_headers = {
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Methods": "*",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Private-Network": "true",
        "Access-Control-Expose-Headers": "*",
        "Access-Control-Max-Age": "86400",
        "Timing-Allow-Origin": "*",
    }
    response = HttpResponse(headers=cors_headers)

    result = SameOriginResponseBoundaryMiddleware(lambda _request: response)(object())

    assert not set(cors_headers).intersection(result.headers)
    assert result.headers["Cross-Origin-Resource-Policy"] == "same-origin"


def test_untrusted_origin_receives_no_cross_origin_permission(client: Client) -> None:
    response = client.get(
        reverse("core:health-live"),
        headers={"Origin": "https://attacker.invalid"},
    )

    assert response.status_code == 200
    assert "Access-Control-Allow-Origin" not in response.headers
    assert "Access-Control-Allow-Credentials" not in response.headers
    assert response.headers["Cross-Origin-Resource-Policy"] == "same-origin"


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


@pytest.mark.parametrize(
    ("forwarded_proto", "expected_proto"),
    [
        ("https", "https"),
        ("http", "http"),
        ("https,http", None),
        ("HTTPS", None),
        ("https\nhttp", None),
    ],
)
def test_proxy_boundary_accepts_only_canonical_scheme_signal(
    forwarded_proto: str,
    expected_proto: str | None,
) -> None:
    observed: dict[str, object] = {}

    def response(request):  # type: ignore[no-untyped-def]
        observed.update(request.META)
        return object()

    request = type(
        "Request",
        (),
        {
            "META": {
                "HTTP_X_FORWARDED_PROTO": forwarded_proto,
                "HTTP_FORWARDED": "host=attacker.invalid;proto=https",
                "HTTP_X_FORWARDED_HOST": "attacker.invalid",
                "HTTP_X_FORWARDED_PORT": "444",
            }
        },
    )()

    ProxyBoundaryMiddleware(response)(request)

    assert observed.get("HTTP_X_FORWARDED_PROTO") == expected_proto
    assert "HTTP_FORWARDED" not in observed
    assert "HTTP_X_FORWARDED_HOST" not in observed
    assert "HTTP_X_FORWARDED_PORT" not in observed


@pytest.mark.parametrize(
    ("host", "expected_status", "expected_downstream"),
    [
        ("budget.example.ts.net", 204, True),
        ("attacker.invalid", 400, False),
    ],
)
@override_settings(ALLOWED_HOSTS=["budget.example.ts.net"])
def test_host_boundary_rejects_unapproved_hosts_on_every_route(
    host: str, expected_status: int, expected_downstream: bool
) -> None:
    downstream_called = False

    def response(request):  # type: ignore[no-untyped-def]
        nonlocal downstream_called
        downstream_called = True
        return HttpResponse(status=204)

    request = RequestFactory().get("/health/live/", HTTP_HOST=host)

    result = HostBoundaryMiddleware(response)(request)

    assert result.status_code == expected_status
    assert downstream_called is expected_downstream
    if expected_status == 400:
        assert result.content == b""


@pytest.mark.parametrize(
    ("path", "secure", "expected_status", "expected_downstream"),
    (
        ("/health/live/", False, 400, False),
        ("/health/live/", True, 204, True),
        ("/health/ready/", False, 400, False),
        ("/api/docs/", False, 400, False),
        ("/accounts/login/", False, 204, True),
    ),
)
def test_nonbrowser_transport_boundary_rejects_plaintext_without_redirecting(
    path: str,
    secure: bool,
    expected_status: int,
    expected_downstream: bool,
) -> None:
    downstream_called = False

    def response(request):  # type: ignore[no-untyped-def]
        nonlocal downstream_called
        downstream_called = True
        return HttpResponse(status=204)

    request = RequestFactory().get(path, secure=secure)
    result = NonBrowserTransportBoundaryMiddleware(response)(request)

    assert result.status_code == expected_status
    assert downstream_called is expected_downstream
    if expected_status == 400:
        assert result.content == b""
        assert "Location" not in result.headers
        assert result.headers["Cache-Control"] == "no-store"
        assert result.headers["X-Content-Type-Options"] == "nosniff"


@pytest.mark.parametrize(
    ("path", "expected_status", "expected_downstream"),
    (
        ("/health/live/", 204, True),
        ("/budget/", 204, True),
        ("/health/live", 404, False),
        ("/health/ready/", 404, False),
        ("/METRICS/", 404, False),
        ("/api/docs/", 404, False),
        ("/internal/openapi.json", 404, False),
        ("/internal/swagger.json", 404, False),
        ("/swagger-ui/", 404, False),
        ("/admin/doc/", 404, False),
        ("/__debug__/", 404, False),
    ),
)
def test_operational_endpoint_boundary_exposes_only_exact_liveness(
    path: str, expected_status: int, expected_downstream: bool
) -> None:
    downstream_called = False

    def response(request):  # type: ignore[no-untyped-def]
        nonlocal downstream_called
        downstream_called = True
        return HttpResponse(status=204)

    request = RequestFactory().get(path)
    result = OperationalEndpointBoundaryMiddleware(response)(request)

    assert result.status_code == expected_status
    assert downstream_called is expected_downstream
    if expected_status == 404:
        assert result.content == b""
