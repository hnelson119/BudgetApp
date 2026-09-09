"""Request diagnostics and sensitive-response controls."""

import logging
import re
import time
import uuid
from collections.abc import Callable

from django.core.exceptions import DisallowedHost
from django.http import HttpRequest, HttpResponse
from django.utils.deprecation import MiddlewareMixin

from .logging import (
    bind_actor_context,
    bind_request_context,
    current_request_id,
    reset_actor_context,
    reset_request_context,
)

request_logger = logging.getLogger("budget.request")
exception_logger = logging.getLogger("budget.exception")

_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$")
_VALID_CONTEXT_ID = re.compile(r"^[0-9a-fA-F-]{32,36}$")
_PUBLIC_OPERATIONAL_PATH = "/health/live/"
_RESERVED_OPERATIONAL_SEGMENTS = frozenset(
    {
        "__debug__",
        "actuator",
        "api-docs",
        "debug",
        "doc",
        "docs",
        "documentation",
        "health",
        "healthz",
        "livez",
        "metrics",
        "openapi",
        "prometheus",
        "readyz",
        "redoc",
        "schema",
        "swagger",
        "swagger-ui",
    }
)
_CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'self'",
        "base-uri 'none'",
        "connect-src 'self'",
        "font-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "img-src 'self' data:",
        "object-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
    )
)


def _is_operational_path(path: str) -> bool:
    segments = (segment.casefold() for segment in path.split("/") if segment)
    return any(
        segment in _RESERVED_OPERATIONAL_SEGMENTS or segment.startswith(("openapi.", "swagger."))
        for segment in segments
    )


class ProxyBoundaryMiddleware:
    """Canonicalize only the proxy signal the private deployment trusts."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        forwarded_proto = request.META.get("HTTP_X_FORWARDED_PROTO")
        if forwarded_proto not in (None, "http", "https"):
            request.META.pop("HTTP_X_FORWARDED_PROTO", None)
        for name in ("HTTP_FORWARDED", "HTTP_X_FORWARDED_HOST", "HTTP_X_FORWARDED_PORT"):
            request.META.pop(name, None)
        return self.get_response(request)


class NonBrowserTransportBoundaryMiddleware:
    """Reject insecure operational requests instead of hiding them behind redirects."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if _is_operational_path(request.path_info) and not request.is_secure():
            response = HttpResponse(status=400)
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
            return response
        return self.get_response(request)


class HostBoundaryMiddleware:
    """Reject every unapproved Host before routing, including host-agnostic health views."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        try:
            request.get_host()
        except DisallowedHost:
            return HttpResponse(status=400)
        return self.get_response(request)


class OperationalEndpointBoundaryMiddleware:
    """Expose only the intentionally public liveness endpoint from reserved namespaces."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        path = request.path_info
        if path == _PUBLIC_OPERATIONAL_PATH:
            return self.get_response(request)
        if _is_operational_path(path):
            return HttpResponse(status=404)
        return self.get_response(request)


def _route_name(request: HttpRequest) -> str:
    match = getattr(request, "resolver_match", None)
    return match.view_name if match and match.view_name else "unresolved"


class RequestContextMiddleware:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        supplied_id = request.headers.get("X-Request-ID", "")
        request_id = supplied_id if _VALID_REQUEST_ID.fullmatch(supplied_id) else uuid.uuid4().hex
        request.request_id = request_id  # type: ignore[attr-defined]
        token = bind_request_context(request_id)
        try:
            response = self.get_response(request)
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            reset_request_context(token)


class ActorContextMiddleware:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        started_at = time.perf_counter()
        actor_id = "-"
        if request.user.is_authenticated:
            actor_id = str(request.user.pk)

        household_id = str(request.session.get("active_household_id", "-"))
        if not _VALID_CONTEXT_ID.fullmatch(household_id):
            household_id = "-"

        tokens = bind_actor_context(actor_id=actor_id, household_id=household_id)
        try:
            response = self.get_response(request)
            if not (request.path.startswith("/health/") and response.status_code < 400):
                level = logging.ERROR if response.status_code >= 500 else logging.INFO
                if 400 <= response.status_code < 500:
                    level = logging.WARNING
                request_logger.log(
                    level,
                    "HTTP request completed.",
                    extra={
                        "event": "http.request.completed",
                        "method": request.method,
                        "route": _route_name(request),
                        "status_code": response.status_code,
                        "duration_ms": round((time.perf_counter() - started_at) * 1000, 2),
                    },
                )
            return response
        finally:
            reset_actor_context(tokens)


class ExceptionLoggingMiddleware(MiddlewareMixin):
    def process_exception(self, request: HttpRequest, exception: Exception) -> None:
        exception_logger.exception(
            "Unhandled request exception.",
            exc_info=(type(exception), exception, exception.__traceback__),
            extra={
                "event": "http.request.unhandled_exception",
                "method": request.method,
                "route": _route_name(request),
                "error_reference": current_request_id(),
            },
        )
        return None


class AuthenticatedNoStoreMiddleware:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)
        if request.user.is_authenticated:
            response.headers["Cache-Control"] = "no-store, private"
            response.headers["Pragma"] = "no-cache"
        return response


class ContentSecurityPolicyMiddleware:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)
        response.headers.setdefault("Content-Security-Policy", _CONTENT_SECURITY_POLICY)
        response.headers.setdefault(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )
        return response
