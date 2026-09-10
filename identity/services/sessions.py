from __future__ import annotations

import secrets
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from django.conf import settings
from django.contrib.auth import logout
from django.contrib.sessions.models import Session
from django.db import transaction
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
SESSION_TERMINATED_ATTRIBUTE = "_budget_session_terminated"
SESSION_ESTABLISHED_ATTRIBUTE = "_budget_session_established"


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


@dataclass(frozen=True, slots=True)
class AdministrativeSessionRevocationResult:
    affected_users: int
    deleted_sessions: int


def terminate_session(request: HttpRequest) -> None:
    """End the server session and mark its response for browser-state cleanup."""

    logout(request)
    setattr(request, SESSION_TERMINATED_ATTRIBUTE, True)


def establish_session_security(request: HttpRequest, user: User) -> None:
    now = int(time.time())
    request.session[SESSION_STARTED_AT] = now
    request.session[SESSION_LAST_SEEN_AT] = now
    request.session[SESSION_USER_VERSION] = user.session_version
    request.session[SESSION_AUTH_VERIFIED_AT] = now
    request.session.set_expiry(0)
    setattr(request, SESSION_ESTABLISHED_ATTRIBUTE, True)


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


@transaction.atomic
def enforce_concurrent_session_limit(
    user: User,
    *,
    current_session_key: str | None,
    maximum: int,
) -> int:
    """Keep the newest authenticated sessions while preserving the current login."""

    if maximum < 1:
        raise ValueError("The concurrent session maximum must be positive.")

    from identity.models import User

    locked_user = User.objects.select_for_update().only("pk", "session_version").get(pk=user.pk)
    active_sessions = [
        session
        for session in Session.objects.select_for_update().filter(expire_date__gt=timezone.now())
        if _belongs_to_active_user_session(session, locked_user)
    ]
    excess = len(active_sessions) - maximum
    if excess <= 0:
        return 0

    def oldest_first(session: Session) -> tuple[datetime, datetime, str]:
        started_at = _session_timestamp(session.get_decoded().get(SESSION_STARTED_AT))
        return (
            started_at or datetime.min.replace(tzinfo=UTC),
            session.expire_date,
            session.session_key,
        )

    candidates = sorted(
        (
            session
            for session in active_sessions
            if not secrets.compare_digest(session.session_key, current_session_key or "")
        ),
        key=oldest_first,
    )
    session_keys = [session.session_key for session in candidates[:excess]]
    deleted, _ = Session.objects.filter(session_key__in=session_keys).delete()
    return deleted


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


def _session_belongs_to_user_identity(session: Session, user_id: str) -> bool:
    data = session.get_decoded()
    return data.get("_auth_user_id") == user_id or data.get(SESSION_PENDING_MFA_USER) == user_id


def delete_sessions_for_user_identity(user_id: str) -> int:
    """Remove authenticated and pending-MFA sessions for one account identity."""

    session_keys = [
        session.session_key
        for session in Session.objects.all()
        if _session_belongs_to_user_identity(session, user_id)
    ]
    if not session_keys:
        return 0
    deleted, _ = Session.objects.filter(session_key__in=session_keys).delete()
    return deleted


def _delete_sessions_for_user(user: User) -> int:
    return delete_sessions_for_user_identity(str(user.pk))


def _validate_administrative_reason(reason: str) -> str:
    normalized = reason.strip()
    if not normalized or len(normalized) > 500:
        raise ValueError("A reason of 1 to 500 characters is required.")
    return normalized


@transaction.atomic
def administratively_revoke_user_sessions(
    user: User,
    *,
    reason: str,
) -> AdministrativeSessionRevocationResult:
    from audit.services import append_event
    from households.models import HouseholdMembership
    from identity.models import User

    normalized_reason = _validate_administrative_reason(reason)
    locked_user = User.objects.select_for_update().get(pk=user.pk)
    previous_version = locked_user.session_version
    locked_user.session_version += 1
    locked_user.save(update_fields=("session_version",))
    deleted_sessions = _delete_sessions_for_user(locked_user)
    request_id = f"session-admin-{uuid.uuid4().hex}"
    memberships = HouseholdMembership.objects.filter(user=locked_user).select_related("household")
    for membership in memberships.order_by("household_id"):
        append_event(
            household=membership.household,
            actor=None,
            action="auth.sessions_administrator_revoked",
            entity_type="identity.user",
            entity_id=locked_user.pk,
            request_id=request_id,
            before={"session_version": previous_version},
            after={
                "scope": "individual",
                "session_version": locked_user.session_version,
                "stored_records_removed": deleted_sessions,
            },
            reason=normalized_reason,
        )
    return AdministrativeSessionRevocationResult(
        affected_users=1,
        deleted_sessions=deleted_sessions,
    )


@transaction.atomic
def administratively_revoke_all_sessions(
    *,
    reason: str,
) -> AdministrativeSessionRevocationResult:
    from audit.services import append_event
    from households.models import HouseholdMembership
    from identity.models import User

    normalized_reason = _validate_administrative_reason(reason)
    users = list(User.objects.select_for_update().order_by("pk"))
    for user in users:
        user.session_version += 1
        user.save(update_fields=("session_version",))
    deleted_sessions, _ = Session.objects.all().delete()

    affected_user_ids = {user.pk for user in users}
    household_members: dict[uuid.UUID, set[uuid.UUID]] = {}
    memberships = HouseholdMembership.objects.filter(user_id__in=affected_user_ids).select_related(
        "household"
    )
    households = {}
    for membership in memberships.order_by("household_id", "user_id"):
        households[membership.household_id] = membership.household
        household_members.setdefault(membership.household_id, set()).add(membership.user_id)

    request_id = f"session-admin-{uuid.uuid4().hex}"
    for household_id, household in households.items():
        append_event(
            household=household,
            actor=None,
            action="auth.sessions_administrator_revoked",
            entity_type="identity.user",
            entity_id="all-accounts",
            request_id=request_id,
            before={"affected_accounts": len(household_members[household_id])},
            after={
                "affected_accounts": len(household_members[household_id]),
                "scope": "all",
            },
            reason=normalized_reason,
        )
    return AdministrativeSessionRevocationResult(
        affected_users=len(users),
        deleted_sessions=deleted_sessions,
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
        terminate_session(request)
        return False

    if now - started_at >= settings.SESSION_ABSOLUTE_TIMEOUT_SECONDS:
        terminate_session(request)
        return False

    if now - last_seen_at >= settings.SESSION_IDLE_TIMEOUT_SECONDS:
        terminate_session(request)
        return False

    if now - last_seen_at >= settings.SESSION_ACTIVITY_UPDATE_SECONDS:
        request.session[SESSION_LAST_SEEN_AT] = now

    return True
