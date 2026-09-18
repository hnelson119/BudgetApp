"""Keep all administration behind the application's MFA and reauthentication flows."""

from typing import Any

from django.contrib.admin import AdminSite
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache

from identity.models import User
from identity.services.mfa import mfa_is_ready
from identity.services.sessions import SESSION_MFA_VERIFIED, recent_authentication_is_valid


class SecureAdminSite(AdminSite):
    def has_permission(self, request: HttpRequest) -> bool:
        return (
            isinstance(request.user, User)
            and super().has_permission(request)
            and request.session.get(SESSION_MFA_VERIFIED) is True
            and recent_authentication_is_valid(request)
            and mfa_is_ready(request.user)
        )

    @method_decorator(never_cache)
    def login(
        self, request: HttpRequest, extra_context: dict[str, Any] | None = None
    ) -> HttpResponse:
        # Never pass submitted credentials to Django's password-only admin login.
        # A fixed return destination also prevents attacker-controlled admin redirects.
        destination = reverse("admin:index", current_app=self.name)
        if not request.user.is_authenticated:
            return redirect_to_login(destination, reverse("identity:login"))
        if not request.user.is_active or not request.user.is_staff:
            raise PermissionDenied
        if self.has_permission(request):
            return HttpResponseRedirect(destination)
        return redirect_to_login(destination, reverse("identity:reauthenticate"))
