from collections.abc import Callable

from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse

from identity.models import MfaCredential, User
from identity.services.mfa import mfa_is_ready
from identity.services.sessions import validate_active_session


class SecureSessionMiddleware:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.user.is_authenticated:
            validate_active_session(request, request.user)
        return self.get_response(request)


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
