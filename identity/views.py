from __future__ import annotations

import logging

from django.conf import settings
from django.contrib.auth import get_user_model, login, logout
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_http_methods, require_POST

from audit.services import append_event
from core.logging import current_request_id
from households.models import HouseholdMembership
from households.services.access import get_active_household
from identity.forms import GENERIC_LOGIN_ERROR, SecureAuthenticationForm
from identity.models import User
from identity.services.sessions import establish_session_security
from identity.services.throttling import (
    clear_login_failures,
    is_login_blocked,
    register_login_failure,
    throttle_keys,
)

security_logger = logging.getLogger("security")


def _authenticated_user(request: HttpRequest) -> User:
    user = request.user
    if not isinstance(user, User) or not user.is_authenticated or user.pk is None:
        raise PermissionDenied
    return user


def _safe_next_url(request: HttpRequest) -> str:
    candidate = request.POST.get("next") or request.GET.get("next") or ""
    if candidate and url_has_allowed_host_and_scheme(
        candidate,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return candidate
    return settings.LOGIN_REDIRECT_URL


def _record_protected_auth_event(
    *,
    user: User,
    action: str,
    request_id: str,
    authenticated_actor: bool,
) -> None:
    memberships = HouseholdMembership.objects.filter(user=user, is_active=True).select_related(
        "household"
    )
    for membership in memberships:
        append_event(
            household=membership.household,
            actor=user if authenticated_actor else None,
            action=action,
            entity_type="identity.user",
            entity_id=user.pk,
            request_id=request_id,
            after={"authentication_method": "password"},
        )


@sensitive_post_parameters("password")
@never_cache
@require_http_methods(["GET", "POST"])
def login_view(request: HttpRequest) -> HttpResponse:
    if request.user.is_authenticated:
        return redirect(settings.LOGIN_REDIRECT_URL)

    status = 200
    form = SecureAuthenticationForm(request=request, data=request.POST or None)
    if request.method == "POST":
        submitted_email = request.POST.get("username", "")
        keys = throttle_keys(request, submitted_email)
        blocked = is_login_blocked(keys)
        if blocked:
            form = SecureAuthenticationForm(
                request=request,
                data=request.POST,
                authentication_blocked=True,
            )

        if form.is_valid() and not blocked:
            user = form.get_user()
            if not isinstance(user, User):
                raise RuntimeError("The authentication backend returned an unexpected user type.")
            login(request, user)
            establish_session_security(request, user)
            user.last_authenticated_at = timezone.now()
            user.save(update_fields=("last_authenticated_at",))

            memberships = list(
                HouseholdMembership.objects.filter(user=user, is_active=True).order_by("joined_at")[
                    :2
                ]
            )
            if len(memberships) == 1:
                request.session["active_household_id"] = str(memberships[0].household_id)

            try:
                _record_protected_auth_event(
                    user=user,
                    action="auth.login_succeeded",
                    request_id=current_request_id(),
                    authenticated_actor=True,
                )
            except Exception:
                logout(request)
                raise

            clear_login_failures(keys)
            security_logger.info(
                "Authentication succeeded.",
                extra={"event": "auth.login_succeeded", "method": "password"},
            )
            return redirect(_safe_next_url(request))

        if not blocked:
            blocked = register_login_failure(keys)

        candidate_user = (
            get_user_model().objects.filter(email__iexact=submitted_email.strip()).first()
        )
        if isinstance(candidate_user, User):
            _record_protected_auth_event(
                user=candidate_user,
                action="auth.login_failed",
                request_id=current_request_id(),
                authenticated_actor=False,
            )

        if not form.non_field_errors():
            form.add_error(None, GENERIC_LOGIN_ERROR)
        security_logger.warning(
            "Authentication failed.",
            extra={"event": "auth.login_failed", "rate_limited": blocked},
        )
        if blocked:
            status = 429

    return render(
        request,
        "identity/login.html",
        {"form": form, "next": _safe_next_url(request)},
        status=status,
    )


@login_required
@require_POST
def logout_view(request: HttpRequest) -> HttpResponse:
    user = _authenticated_user(request)
    household = get_active_household(request)
    append_event(
        household=household,
        actor=user,
        action="auth.logout",
        entity_type="identity.user",
        entity_id=user.pk,
        request_id=current_request_id(),
    )
    security_logger.info("User logged out.", extra={"event": "auth.logout"})
    logout(request)
    return redirect(settings.LOGOUT_REDIRECT_URL)


@login_required
@require_POST
@transaction.atomic
def logout_all_devices_view(request: HttpRequest) -> HttpResponse:
    household = get_active_household(request)
    request_user = _authenticated_user(request)
    user = User.objects.select_for_update().get(pk=request_user.pk)
    previous_version = user.session_version
    user.session_version += 1
    user.save(update_fields=("session_version",))
    append_event(
        household=household,
        actor=user,
        action="auth.sessions_revoked",
        entity_type="identity.user",
        entity_id=user.pk,
        request_id=current_request_id(),
        before={"session_version": previous_version},
        after={"session_version": user.session_version},
    )
    security_logger.warning(
        "All user sessions were revoked.",
        extra={"event": "auth.sessions_revoked"},
    )
    logout(request)
    return redirect(reverse("identity:login"))
