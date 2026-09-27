from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import timedelta

from django.db import transaction
from django.http import HttpRequest, HttpResponse
from django.utils import timezone

from core.errors import rate_limited
from core.logging import current_request_id
from identity.models import ApplicationThrottle, User


@dataclass(frozen=True, slots=True)
class ApplicationThrottleDecision:
    allowed: bool
    retry_after_seconds: int


@transaction.atomic
def consume_application_budget(
    *,
    user: User,
    scope: str,
    maximum: int,
    window_seconds: int,
) -> ApplicationThrottleDecision:
    if not scope or len(scope) > 64:
        raise ValueError("application throttle scope must contain 1 to 64 characters")
    if maximum < 1 or window_seconds < 1:
        raise ValueError("application throttle limits must be positive")

    now = timezone.now()
    window_start = now - timedelta(seconds=window_seconds)
    throttle, _ = ApplicationThrottle.objects.select_for_update().get_or_create(
        user=user,
        scope=scope,
        defaults={
            "window_started_at": now,
            "last_request_at": now,
        },
    )
    if throttle.window_started_at <= window_start:
        throttle.window_started_at = now
        throttle.request_count = 0

    throttle.last_request_at = now
    if throttle.request_count >= maximum:
        throttle.save(update_fields=("window_started_at", "request_count", "last_request_at"))
        retry_after = max(
            1,
            math.ceil(
                (
                    throttle.window_started_at + timedelta(seconds=window_seconds) - now
                ).total_seconds()
            ),
        )
        return ApplicationThrottleDecision(allowed=False, retry_after_seconds=retry_after)

    throttle.request_count += 1
    throttle.save(update_fields=("window_started_at", "request_count", "last_request_at"))
    return ApplicationThrottleDecision(allowed=True, retry_after_seconds=0)


def enforce_application_budget(
    request: HttpRequest,
    *,
    user: User,
    scope: str,
    maximum: int,
    window_seconds: int,
) -> HttpResponse | None:
    decision = consume_application_budget(
        user=user,
        scope=scope,
        maximum=maximum,
        window_seconds=window_seconds,
    )
    if decision.allowed:
        return None
    response = rate_limited(request)
    response.headers["Retry-After"] = str(decision.retry_after_seconds)
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Error-Reference"] = current_request_id()
    return response
