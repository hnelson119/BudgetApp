from __future__ import annotations

import time
from typing import TYPE_CHECKING

from django.conf import settings
from django.contrib.auth import logout
from django.http import HttpRequest

if TYPE_CHECKING:
    from identity.models import User

SESSION_STARTED_AT = "security_started_at"
SESSION_LAST_SEEN_AT = "security_last_seen_at"
SESSION_USER_VERSION = "security_user_version"
SESSION_AUTH_VERIFIED_AT = "security_auth_verified_at"
SESSION_PENDING_MFA_USER = "security_pending_mfa_user"
SESSION_PENDING_MFA_STARTED_AT = "security_pending_mfa_started_at"
SESSION_PENDING_MFA_VERSION = "security_pending_mfa_version"
SESSION_RECOVERY_CONFIRMATION = "security_recovery_confirmation"


def establish_session_security(request: HttpRequest, user: User) -> None:
    now = int(time.time())
    request.session[SESSION_STARTED_AT] = now
    request.session[SESSION_LAST_SEEN_AT] = now
    request.session[SESSION_USER_VERSION] = user.session_version
    request.session[SESSION_AUTH_VERIFIED_AT] = now
    request.session.set_expiry(0)


def establish_pending_mfa(request: HttpRequest, user: User) -> None:
    request.session.flush()
    request.session[SESSION_PENDING_MFA_USER] = str(user.pk)
    request.session[SESSION_PENDING_MFA_STARTED_AT] = int(time.time())
    request.session[SESSION_PENDING_MFA_VERSION] = user.session_version
    request.session.set_expiry(0)


def clear_pending_mfa(request: HttpRequest) -> None:
    for key in (
        SESSION_PENDING_MFA_USER,
        SESSION_PENDING_MFA_STARTED_AT,
        SESSION_PENDING_MFA_VERSION,
    ):
        request.session.pop(key, None)


def mark_recent_authentication(request: HttpRequest) -> None:
    request.session.cycle_key()
    request.session[SESSION_AUTH_VERIFIED_AT] = int(time.time())


def recent_authentication_is_valid(request: HttpRequest) -> bool:
    verified_at = request.session.get(SESSION_AUTH_VERIFIED_AT)
    return isinstance(verified_at, int) and (
        int(time.time()) - verified_at < settings.RECENT_AUTH_TIMEOUT_SECONDS
    )


def get_pending_mfa_user(request: HttpRequest) -> User | None:
    from identity.models import User

    user_id = request.session.get(SESSION_PENDING_MFA_USER)
    started_at = request.session.get(SESSION_PENDING_MFA_STARTED_AT)
    version = request.session.get(SESSION_PENDING_MFA_VERSION)
    if (
        not isinstance(user_id, str)
        or not isinstance(started_at, int)
        or not isinstance(version, int)
        or int(time.time()) - started_at >= settings.MFA_PENDING_TIMEOUT_SECONDS
    ):
        clear_pending_mfa(request)
        return None

    user = User.objects.filter(pk=user_id, is_active=True, session_version=version).first()
    if user is None:
        clear_pending_mfa(request)
    return user


def validate_active_session(request: HttpRequest, user: User) -> bool:
    now = int(time.time())
    started_at = request.session.get(SESSION_STARTED_AT)
    last_seen_at = request.session.get(SESSION_LAST_SEEN_AT)
    session_version = request.session.get(SESSION_USER_VERSION)

    if (
        not isinstance(started_at, int)
        or not isinstance(last_seen_at, int)
        or not isinstance(session_version, int)
    ):
        establish_session_security(request, user)
        return True

    if session_version != user.session_version:
        logout(request)
        return False

    if now - started_at >= settings.SESSION_ABSOLUTE_TIMEOUT_SECONDS:
        logout(request)
        return False

    if now - last_seen_at >= settings.SESSION_IDLE_TIMEOUT_SECONDS:
        logout(request)
        return False

    if now - last_seen_at >= settings.SESSION_ACTIVITY_UPDATE_SECONDS:
        request.session[SESSION_LAST_SEEN_AT] = now

    return True
