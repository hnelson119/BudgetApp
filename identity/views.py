from __future__ import annotations

import logging
from urllib.parse import urlencode

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import password_changed
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
from identity.forms import (
    GENERIC_LOGIN_ERROR,
    ForgottenPasswordRecoveryForm,
    MfaVerificationForm,
    ReauthenticationForm,
    RecoveryCodesConfirmationForm,
    SecureAuthenticationForm,
    SecurePasswordChangeForm,
    SessionRevocationForm,
    TotpEnrollmentForm,
)
from identity.models import MfaCredential, User
from identity.services.mfa import (
    begin_enrollment,
    confirm_enrollment,
    confirm_recovery_codes_saved,
    mfa_is_ready,
    mfa_verification_required,
    provisioning_qr_data_uri,
    reset_mfa,
    verify_and_consume_recovery_code,
    verify_and_consume_totp,
)
from identity.services.recovery import recover_forgotten_password
from identity.services.sessions import (
    SESSION_MFA_VERIFIED,
    SESSION_RECOVERY_CONFIRMATION,
    active_sessions_for_user,
    clear_pending_mfa,
    establish_pending_mfa,
    establish_session_security,
    get_pending_mfa_user,
    mark_recent_authentication,
    recent_authentication_is_valid,
    revoke_user_session,
    terminate_session,
)
from identity.services.throttling import (
    clear_login_failures,
    is_login_blocked,
    register_login_failure,
    throttle_keys,
)

security_logger = logging.getLogger("security")
MFA_GENERIC_ERROR = "The verification code was not accepted."


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
    method: str,
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
            after={"authentication_method": method},
        )


def _set_active_household(request: HttpRequest, user: User) -> None:
    memberships = list(
        HouseholdMembership.objects.filter(user=user, is_active=True).order_by("joined_at")[:2]
    )
    if len(memberships) == 1:
        request.session["active_household_id"] = str(memberships[0].household_id)


def _reauthentication_redirect(destination: str) -> HttpResponse:
    query = urlencode({"next": destination})
    return redirect(f"{reverse('identity:reauthenticate')}?{query}")


def _record_account_security_event(
    *,
    user: User,
    action: str,
    before: dict[str, object] | None = None,
    after: dict[str, object] | None = None,
) -> None:
    memberships = tuple(
        HouseholdMembership.objects.filter(user=user, is_active=True)
        .select_related("household")
        .order_by("household_id")
    )
    if not memberships:
        raise PermissionDenied
    for membership in memberships:
        append_event(
            household=membership.household,
            actor=user,
            action=action,
            entity_type="identity.user",
            entity_id=user.pk,
            request_id=current_request_id(),
            before=before,
            after=after,
        )


def _complete_login(request: HttpRequest, user: User, *, method: str) -> None:
    login(request, user)
    clear_pending_mfa(request)
    establish_session_security(request, user)
    request.session[SESSION_MFA_VERIFIED] = True
    _set_active_household(request, user)
    user.last_authenticated_at = timezone.now()
    user.save(update_fields=("last_authenticated_at",))
    _record_protected_auth_event(
        user=user,
        action="auth.login_succeeded",
        request_id=current_request_id(),
        authenticated_actor=True,
        method=method,
    )


@sensitive_post_parameters("code", "new_password1", "new_password2")
@never_cache
@require_http_methods(["GET", "POST"])
def password_recovery_view(request: HttpRequest) -> HttpResponse:
    if request.user.is_authenticated:
        return redirect(settings.LOGIN_REDIRECT_URL)

    form = ForgottenPasswordRecoveryForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        email = form.cleaned_data["email"]
        keys = throttle_keys(request, email, scope="password_recovery")
        blocked = is_login_blocked(keys)
        accepted = False
        if not blocked:
            result = recover_forgotten_password(
                email=email,
                code=form.cleaned_data["code"],
                new_password=form.cleaned_data["new_password1"],
                request_id=current_request_id(),
            )
            accepted = result.accepted

        if accepted:
            clear_login_failures(keys)
        elif not blocked:
            blocked = register_login_failure(keys)
        security_logger.warning(
            "Password recovery submission processed.",
            extra={
                "event": "auth.password_recovery_submitted",
                "accepted": accepted,
                "rate_limited": blocked,
            },
        )
        return render(
            request,
            "identity/password_recovery_submitted.html",
            status=429 if blocked else 200,
        )

    return render(
        request,
        "identity/password_recovery.html",
        {"form": form},
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

            if mfa_verification_required(user):
                establish_pending_mfa(request, user)
                security_logger.info(
                    "Password authentication accepted; MFA is pending.",
                    extra={"event": "auth.password_accepted"},
                )
                query = urlencode({"next": _safe_next_url(request)})
                return redirect(f"{reverse('identity:mfa-verify')}?{query}")

            login(request, user)
            establish_session_security(request, user)
            _set_active_household(request, user)
            try:
                _record_protected_auth_event(
                    user=user,
                    action="auth.mfa_enrollment_required",
                    request_id=current_request_id(),
                    authenticated_actor=True,
                    method="password",
                )
            except Exception:
                logout(request)
                raise
            clear_login_failures(keys)
            return redirect(reverse("identity:mfa-enroll"))

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
                method="password",
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


@sensitive_post_parameters("code")
@never_cache
@require_http_methods(["GET", "POST"])
def mfa_verify_view(request: HttpRequest) -> HttpResponse:
    if request.user.is_authenticated:
        return redirect(settings.LOGIN_REDIRECT_URL)
    user = get_pending_mfa_user(request)
    if user is None:
        return redirect(reverse("identity:login"))

    form = MfaVerificationForm(request.POST or None)
    status = 200
    if request.method == "POST" and form.is_valid():
        keys = throttle_keys(request, str(user.pk), scope="mfa")
        blocked = is_login_blocked(keys)
        method = "totp"
        verified = False
        if not blocked:
            code = form.cleaned_data["code"]
            with transaction.atomic():
                if len(code) == 6 and code.isdigit():
                    verified = verify_and_consume_totp(user, code)
                else:
                    method = "recovery_code"
                    verified = verify_and_consume_recovery_code(user, code)
                if verified:
                    _complete_login(request, user, method=f"password_{method}")

        if verified:
            clear_login_failures(keys)
            clear_login_failures(throttle_keys(request, user.email))
            security_logger.info(
                "Multi-factor authentication succeeded.",
                extra={"event": "auth.mfa_succeeded", "method": method},
            )
            return redirect(_safe_next_url(request))

        if not blocked:
            blocked = register_login_failure(keys)
        _record_protected_auth_event(
            user=user,
            action="auth.mfa_failed",
            request_id=current_request_id(),
            authenticated_actor=False,
            method="totp_or_recovery",
        )
        form.add_error(None, MFA_GENERIC_ERROR)
        security_logger.warning(
            "Multi-factor authentication failed.",
            extra={"event": "auth.mfa_failed", "rate_limited": blocked},
        )
        if blocked:
            status = 429

    return render(
        request,
        "identity/mfa_verify.html",
        {"form": form, "next": _safe_next_url(request)},
        status=status,
    )


@login_required
@sensitive_post_parameters("code")
@never_cache
@require_http_methods(["GET", "POST"])
def mfa_enroll_view(request: HttpRequest) -> HttpResponse:
    user = _authenticated_user(request)
    if mfa_is_ready(user):
        return redirect(settings.LOGIN_REDIRECT_URL)

    enrollment = begin_enrollment(user)
    if enrollment.credential.confirmed_at is not None:
        return redirect(reverse("identity:mfa-recovery-confirm"))

    form = TotpEnrollmentForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        household = get_active_household(request)
        with transaction.atomic():
            confirmed = confirm_enrollment(user, form.cleaned_data["code"])
            if confirmed is not None:
                user.refresh_from_db()
                append_event(
                    household=household,
                    actor=user,
                    action="auth.mfa_enrolled",
                    entity_type="identity.user",
                    entity_id=user.pk,
                    request_id=current_request_id(),
                    after={"method": "totp", "recovery_code_count": len(confirmed.recovery_codes)},
                )
        if confirmed is not None:
            establish_session_security(request, user)
            request.session[SESSION_RECOVERY_CONFIRMATION] = str(enrollment.credential.pk)
            security_logger.warning(
                "Multi-factor authentication was enrolled.",
                extra={"event": "auth.mfa_enrolled", "method": "totp"},
            )
            return render(
                request,
                "identity/recovery_codes.html",
                {
                    "codes": confirmed.recovery_codes,
                    "form": RecoveryCodesConfirmationForm(),
                },
            )
        form.add_error("code", "That code was not accepted. Wait for a new code and try again.")

    return render(
        request,
        "identity/mfa_enroll.html",
        {
            "form": form,
            "secret": enrollment.secret,
            "qr_data_uri": provisioning_qr_data_uri(user=user, secret=enrollment.secret),
        },
    )


@login_required
@never_cache
@require_http_methods(["GET", "POST"])
def mfa_recovery_confirm_view(request: HttpRequest) -> HttpResponse:
    user = _authenticated_user(request)
    if mfa_is_ready(user):
        return redirect(settings.LOGIN_REDIRECT_URL)

    credential = MfaCredential.objects.filter(user=user, confirmed_at__isnull=False).first()
    if credential is None:
        return redirect(reverse("identity:mfa-enroll"))

    form = RecoveryCodesConfirmationForm(request.POST or None)
    expected_credential = request.session.get(SESSION_RECOVERY_CONFIRMATION)
    can_confirm = expected_credential == str(credential.pk)
    if request.method == "POST" and can_confirm and form.is_valid():
        household = get_active_household(request)
        with transaction.atomic():
            if not confirm_recovery_codes_saved(user):
                raise RuntimeError("Recovery-code confirmation state is invalid.")
            append_event(
                household=household,
                actor=user,
                action="auth.recovery_codes_confirmed",
                entity_type="identity.user",
                entity_id=user.pk,
                request_id=current_request_id(),
                after={"stored_as": "one_way_hashes"},
            )
        request.session.pop(SESSION_RECOVERY_CONFIRMATION, None)
        security_logger.warning(
            "Recovery codes were confirmed.",
            extra={"event": "auth.recovery_codes_confirmed"},
        )
        return redirect(settings.LOGIN_REDIRECT_URL)

    return render(
        request,
        "identity/recovery_codes_confirm.html",
        {"form": form, "can_confirm": can_confirm},
    )


@login_required
@require_POST
@transaction.atomic
def mfa_enrollment_restart_view(request: HttpRequest) -> HttpResponse:
    user = _authenticated_user(request)
    if mfa_is_ready(user):
        raise PermissionDenied
    household = get_active_household(request)
    reset_mfa(user)
    user.refresh_from_db()
    append_event(
        household=household,
        actor=user,
        action="auth.mfa_enrollment_restarted",
        entity_type="identity.user",
        entity_id=user.pk,
        request_id=current_request_id(),
    )
    establish_session_security(request, user)
    request.session.pop(SESSION_RECOVERY_CONFIRMATION, None)
    return redirect(reverse("identity:mfa-enroll"))


@login_required
@sensitive_post_parameters("password", "code")
@never_cache
@require_http_methods(["GET", "POST"])
def reauthenticate_view(request: HttpRequest) -> HttpResponse:
    user = _authenticated_user(request)
    household = get_active_household(request)
    form = ReauthenticationForm(request.POST or None)
    status = 200
    if request.method == "POST" and form.is_valid():
        keys = throttle_keys(request, str(user.pk), scope="reauthentication")
        blocked = is_login_blocked(keys)
        method = "totp"
        verified = False
        if not blocked and user.check_password(form.cleaned_data["password"]):
            code = form.cleaned_data["code"]
            with transaction.atomic():
                if len(code) == 6 and code.isdigit():
                    verified = verify_and_consume_totp(user, code)
                else:
                    method = "recovery_code"
                    verified = verify_and_consume_recovery_code(user, code)
                if verified:
                    append_event(
                        household=household,
                        actor=user,
                        action="auth.reauthentication_succeeded",
                        entity_type="identity.user",
                        entity_id=user.pk,
                        request_id=current_request_id(),
                        after={"method": f"password_{method}"},
                    )

        if verified:
            clear_login_failures(keys)
            mark_recent_authentication(request)
            security_logger.info(
                "Sensitive-action reauthentication succeeded.",
                extra={"event": "auth.reauthentication_succeeded", "method": method},
            )
            return redirect(_safe_next_url(request))

        if not blocked:
            blocked = register_login_failure(keys)
        append_event(
            household=household,
            actor=user,
            action="auth.reauthentication_failed",
            entity_type="identity.user",
            entity_id=user.pk,
            request_id=current_request_id(),
        )
        form.add_error(None, "Reauthentication was not accepted.")
        security_logger.warning(
            "Sensitive-action reauthentication failed.",
            extra={"event": "auth.reauthentication_failed", "rate_limited": blocked},
        )
        if blocked:
            status = 429

    return render(
        request,
        "identity/reauthenticate.html",
        {"form": form, "next": _safe_next_url(request)},
        status=status,
    )


@login_required
@never_cache
@require_http_methods(["GET"])
def account_security_view(request: HttpRequest) -> HttpResponse:
    user = _authenticated_user(request)
    household = get_active_household(request)
    return render(
        request,
        "identity/account_security.html",
        {
            "household": household,
            "active_sessions": active_sessions_for_user(
                user,
                current_session_key=request.session.session_key,
            ),
            "recent_authentication": recent_authentication_is_valid(request),
            "current_nav": "account",
        },
    )


@login_required
@sensitive_post_parameters("old_password", "new_password1", "new_password2")
@never_cache
@require_http_methods(["GET", "POST"])
def password_change_view(request: HttpRequest) -> HttpResponse:
    request_user = _authenticated_user(request)
    household = get_active_household(request)
    if not recent_authentication_is_valid(request):
        return _reauthentication_redirect(reverse("identity:password-change"))

    form = SecurePasswordChangeForm(user=request_user, data=request.POST or None)
    changed_user: User | None = None
    if request.method == "POST" and form.is_valid():
        with transaction.atomic():
            locked_user = User.objects.select_for_update().get(pk=request_user.pk)
            if not locked_user.check_password(form.cleaned_data["old_password"]):
                form.add_error("old_password", "The current password was not accepted.")
            else:
                previous_version = locked_user.session_version
                locked_user.set_password(form.cleaned_data["new_password1"])
                locked_user.session_version += 1
                locked_user.save(update_fields=("password", "session_version"))
                password_changed(form.cleaned_data["new_password1"], locked_user)
                _record_account_security_event(
                    user=locked_user,
                    action="auth.password_changed",
                    before={"session_version": previous_version},
                    after={
                        "credential_changed": True,
                        "other_sessions_revoked": True,
                        "session_version": locked_user.session_version,
                    },
                )
                changed_user = locked_user

    if changed_user is not None:
        update_session_auth_hash(request, changed_user)
        establish_session_security(request, changed_user)
        messages.success(request, "Password changed. Other signed-in sessions were revoked.")
        security_logger.warning(
            "Password changed and other sessions revoked.",
            extra={"event": "auth.password_changed"},
        )
        return redirect(reverse("identity:account-security"))

    return render(
        request,
        "identity/password_change.html",
        {
            "household": household,
            "form": form,
            "current_nav": "account",
        },
    )


@login_required
@require_POST
@transaction.atomic
def session_revoke_view(request: HttpRequest) -> HttpResponse:
    user = _authenticated_user(request)
    if not recent_authentication_is_valid(request):
        return _reauthentication_redirect(reverse("identity:account-security"))

    form = SessionRevocationForm(request.POST)
    if not form.is_valid():
        raise PermissionDenied
    result = revoke_user_session(
        user,
        reference=form.cleaned_data["session_reference"],
        current_session_key=request.session.session_key,
    )
    if result is None:
        messages.info(request, "That session is no longer active.")
        return redirect(reverse("identity:account-security"))

    scope = "current" if result.is_current else "other"
    _record_account_security_event(
        user=user,
        action="auth.session_revoked",
        after={"scope": scope},
    )
    security_logger.warning(
        "One user session was revoked.",
        extra={"event": "auth.session_revoked", "scope": scope},
    )
    if result.is_current:
        terminate_session(request)
        return redirect(reverse("identity:login"))
    messages.success(request, "The selected session was revoked.")
    return redirect(reverse("identity:account-security"))


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
    terminate_session(request)
    return redirect(settings.LOGOUT_REDIRECT_URL)


@login_required
@require_POST
@transaction.atomic
def logout_all_devices_view(request: HttpRequest) -> HttpResponse:
    if not recent_authentication_is_valid(request):
        return _reauthentication_redirect(reverse("identity:account-security"))
    request_user = _authenticated_user(request)
    user = User.objects.select_for_update().get(pk=request_user.pk)
    previous_version = user.session_version
    user.session_version += 1
    user.save(update_fields=("session_version",))
    _record_account_security_event(
        user=user,
        action="auth.sessions_revoked",
        before={"session_version": previous_version},
        after={"session_version": user.session_version},
    )
    security_logger.warning(
        "All user sessions were revoked.",
        extra={"event": "auth.sessions_revoked"},
    )
    terminate_session(request)
    return redirect(reverse("identity:login"))
