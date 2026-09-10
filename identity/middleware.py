import logging
from collections.abc import Callable

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse

from identity.models import MfaCredential, User
from identity.services.mfa import mfa_is_ready
from identity.services.sessions import (
    SESSION_ESTABLISHED_ATTRIBUTE,
    SESSION_TERMINATED_ATTRIBUTE,
    enforce_concurrent_session_limit,
    validate_active_session,
)

_CLEAR_SITE_DATA = '"cache", "cookies", "storage"'
security_logger = logging.getLogger("security")


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
