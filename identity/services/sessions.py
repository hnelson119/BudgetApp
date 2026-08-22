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


def establish_session_security(request: HttpRequest, user: User) -> None:
    now = int(time.time())
    request.session[SESSION_STARTED_AT] = now
    request.session[SESSION_LAST_SEEN_AT] = now
    request.session[SESSION_USER_VERSION] = user.session_version
    request.session.set_expiry(settings.SESSION_ABSOLUTE_TIMEOUT_SECONDS)


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
