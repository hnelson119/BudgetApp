from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.http import HttpRequest
from django.utils import timezone

from identity.models import LoginThrottle


@dataclass(frozen=True)
class LoginThrottleKeys:
    identifier: str
    network: str

    def ordered(self) -> tuple[str, str]:
        return tuple(sorted((self.identifier, self.network)))  # type: ignore[return-value]


def _pseudonymize(kind: str, value: str) -> str:
    message = f"household-budget:login-throttle:{kind}:{value}".encode()
    return hmac.new(settings.SECRET_KEY.encode(), message, hashlib.sha256).hexdigest()


def throttle_keys(request: HttpRequest, email: str) -> LoginThrottleKeys:
    normalized_email = email.strip().casefold()
    remote_address = str(request.META.get("REMOTE_ADDR") or "unknown")
    return LoginThrottleKeys(
        identifier=_pseudonymize("identifier", normalized_email),
        network=_pseudonymize("network", remote_address),
    )


def is_login_blocked(keys: LoginThrottleKeys) -> bool:
    now = timezone.now()
    return LoginThrottle.objects.filter(
        key_hash__in=keys.ordered(),
        blocked_until__gt=now,
    ).exists()


@transaction.atomic
def register_login_failure(keys: LoginThrottleKeys) -> bool:
    now = timezone.now()
    window_start = now - timedelta(seconds=settings.LOGIN_RATE_LIMIT_WINDOW_SECONDS)
    blocked = False

    for key_hash in keys.ordered():
        throttle, _ = LoginThrottle.objects.select_for_update().get_or_create(
            key_hash=key_hash,
            defaults={"window_started_at": now},
        )
        if throttle.window_started_at < window_start:
            throttle.window_started_at = now
            throttle.failure_count = 0
            throttle.blocked_until = None

        throttle.failure_count += 1
        throttle.last_failure_at = now
        if throttle.failure_count >= settings.LOGIN_RATE_LIMIT_FAILURES:
            throttle.blocked_until = now + timedelta(
                seconds=settings.LOGIN_RATE_LIMIT_BLOCK_SECONDS
            )
            blocked = True
        throttle.save(
            update_fields=(
                "window_started_at",
                "failure_count",
                "blocked_until",
                "last_failure_at",
            )
        )

    return blocked


def clear_login_failures(keys: LoginThrottleKeys) -> None:
    LoginThrottle.objects.filter(key_hash__in=keys.ordered()).delete()
