import logging
from collections.abc import Callable

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin

from identity.models import MfaCredential, User
from identity.services.application_throttling import enforce_application_budget
from identity.services.mfa import mfa_is_ready
from identity.services.sessions import (
    SESSION_ESTABLISHED_ATTRIBUTE,
    SESSION_TERMINATED_ATTRIBUTE,
    enforce_concurrent_session_limit,
    validate_active_session,
)

_CLEAR_SITE_DATA = '"cache", "cookies", "storage"'
security_logger = logging.getLogger("security")


class ApplicationRateLimitMiddleware(MiddlewareMixin):
    """Bound every authenticated state-changing HTTP request per account."""

    _MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
    _SECURITY_TERMINATION_ROUTES = frozenset(
        {"identity:logout", "identity:logout-all", "identity:session-revoke"}
    )

    def process_view(
        self,
        request: HttpRequest,
        _view_func: object,
        _view_args: object,
        _view_kwargs: object,
    ) -> HttpResponse | None:
        user = request.user
        route = request.resolver_match.view_name if request.resolver_match else ""
        if route in self._SECURITY_TERMINATION_ROUTES:
            return None
        if (
            isinstance(user, User)
            and user.is_authenticated
            and request.method in self._MUTATING_METHODS
        ):
            response = enforce_application_budget(
                request,
                user=user,
                scope="authenticated-mutation",
                maximum=settings.APPLICATION_MUTATION_RATE_LIMIT,
                window_seconds=settings.APPLICATION_MUTATION_RATE_WINDOW_SECONDS,
            )
            if response is not None:
                security_logger.warning(
                    "Authenticated mutation rate limited.",
                    extra={"event": "anti_automation.rate_limited", "scope": "mutation"},
                )
                return response
        return None


class ConcurrentSessionLimitMiddleware:
    """Enforce the account session cap after SessionMiddleware saves a new login."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)
        user = getattr(request, "user", None)
        if getattr(request, SESSION_ESTABLISHED_ATTRIBUTE, False) and isinstance(user, User):
            evicted = enforce_concurrent_session_limit(
                user,
                current_session_key=request.session.session_key,
                maximum=settings.MAX_CONCURRENT_SESSIONS,
            )
            if evicted:
                security_logger.warning(
                    "Oldest user sessions revoked at the concurrent-session limit.",
                    extra={"event": "auth.session_revoked", "scope": "concurrent_limit"},
                )
        return response


class SecureSessionMiddleware:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.user.is_authenticated:
            validate_active_session(request, request.user)
        elif (
            settings.SESSION_COOKIE_NAME in request.COOKIES and request.session.session_key is None
        ):
            setattr(request, SESSION_TERMINATED_ATTRIBUTE, True)
        response = self.get_response(request)
        if getattr(request, SESSION_TERMINATED_ATTRIBUTE, False):
            response.headers["Cache-Control"] = "no-store, private"
            response.headers["Pragma"] = "no-cache"
            if request.is_secure():
                response.headers["Clear-Site-Data"] = _CLEAR_SITE_DATA
        return response


class MfaRequiredMiddleware:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        user = request.user
        if not isinstance(user, User) or not user.is_authenticated:
            return self.get_response(request)
        if mfa_is_ready(user):
            return self.get_response(request)

        allowed_paths = {
            reverse("identity:logout"),
            reverse("identity:mfa-enroll"),
            reverse("identity:mfa-enrollment-restart"),
            reverse("identity:mfa-recovery-confirm"),
        }
        if request.path in allowed_paths:
            return self.get_response(request)

        credential = MfaCredential.objects.filter(user=user).only("confirmed_at").first()
        if credential is not None and credential.confirmed_at is not None:
            return redirect(reverse("identity:mfa-recovery-confirm"))
        return redirect(reverse("identity:mfa-enroll"))
