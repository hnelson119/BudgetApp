from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from django.conf import settings
from django.contrib.auth import logout
from django.contrib.sessions.models import Session
from django.http import HttpRequest
from django.utils import timezone
from django.utils.crypto import salted_hmac

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


@dataclass(frozen=True, slots=True)
class ActiveSession:
    reference: str
    is_current: bool
    started_at: datetime | None
    last_seen_at: datetime | None
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class SessionRevocationResult:
    is_current: bool


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


def _session_reference(session_key: str) -> str:
    return salted_hmac(
        "identity.active-session-reference",
        session_key,
        algorithm="sha256",
    ).hexdigest()


def _session_timestamp(value: object) -> datetime | None:
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    try:
        return datetime.fromtimestamp(value, tz=UTC)
    except (OSError, OverflowError, ValueError):
        return None


def _belongs_to_active_user_session(session: Session, user: User) -> bool:
    data = session.get_decoded()
    return (
        data.get("_auth_user_id") == str(user.pk)
        and data.get(SESSION_USER_VERSION) == user.session_version
    )


def active_sessions_for_user(
    user: User,
    *,
    current_session_key: str | None,
) -> tuple[ActiveSession, ...]:
    rows: list[ActiveSession] = []
    sessions = Session.objects.filter(expire_date__gt=timezone.now()).order_by("-expire_date")
    for session in sessions:
        if not _belongs_to_active_user_session(session, user):
            continue
        data = session.get_decoded()
        rows.append(
            ActiveSession(
                reference=_session_reference(session.session_key),
                is_current=secrets.compare_digest(
                    session.session_key,
                    current_session_key or "",
                ),
                started_at=_session_timestamp(data.get(SESSION_STARTED_AT)),
                last_seen_at=_session_timestamp(data.get(SESSION_LAST_SEEN_AT)),
                expires_at=session.expire_date,
            )
        )
    return tuple(sorted(rows, key=lambda row: not row.is_current))


def revoke_user_session(
    user: User,
    *,
    reference: str,
    current_session_key: str | None,
) -> SessionRevocationResult | None:
    sessions = Session.objects.filter(expire_date__gt=timezone.now())
    for session in sessions:
        if not _belongs_to_active_user_session(session, user):
            continue
        if not secrets.compare_digest(_session_reference(session.session_key), reference):
            continue
        is_current = secrets.compare_digest(session.session_key, current_session_key or "")
        deleted, _ = Session.objects.filter(session_key=session.session_key).delete()
        if deleted == 0:
            return None
        return SessionRevocationResult(is_current=is_current)
    return None


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
