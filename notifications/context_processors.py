from __future__ import annotations

import uuid

from django.http import HttpRequest

from households.models import HouseholdMembership
from notifications.models import Notification


def notification_badge(request: HttpRequest) -> dict[str, int]:
    if not request.user.is_authenticated:
        return {"unread_notification_count": 0}
    selected = request.session.get("active_household_id")
    try:
        household_id = uuid.UUID(str(selected))
    except (TypeError, ValueError, AttributeError):
        return {"unread_notification_count": 0}
    if not HouseholdMembership.objects.filter(
        household_id=household_id,
        user=request.user,
        is_active=True,
    ).exists():
        return {"unread_notification_count": 0}
    return {
        "unread_notification_count": Notification.objects.filter(
            household_id=household_id,
            recipient=request.user,
            read_at__isnull=True,
            dismissed_at__isnull=True,
            resolved_at__isnull=True,
        ).count()
    }
