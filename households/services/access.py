from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from django.core.exceptions import PermissionDenied

from households.models import Household, HouseholdMembership

if TYPE_CHECKING:
    from django.http import HttpRequest

    from identity.models import User


def require_household_membership(user: User, household: Household) -> None:
    if not user.is_authenticated:
        raise PermissionDenied
    if not HouseholdMembership.objects.filter(
        user=user,
        household=household,
        is_active=True,
    ).exists():
        raise PermissionDenied


def get_active_household(request: HttpRequest) -> Household:
    if not request.user.is_authenticated:
        raise PermissionDenied

    memberships = HouseholdMembership.objects.filter(
        user=request.user,
        is_active=True,
    ).select_related("household")
    selected_id = request.session.get("active_household_id")
    if selected_id:
        try:
            selected_uuid = uuid.UUID(str(selected_id))
        except (ValueError, TypeError, AttributeError):
            selected_uuid = None
        if selected_uuid is not None:
            selected = memberships.filter(household_id=selected_uuid).first()
            if selected is not None:
                return selected.household
        request.session.pop("active_household_id", None)

    first_two = list(memberships.order_by("joined_at")[:2])
    if len(first_two) != 1:
        raise PermissionDenied

    household = first_two[0].household
    request.session["active_household_id"] = str(household.pk)
    return household
