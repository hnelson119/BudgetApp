from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import transaction

from audit.services import append_event
from households.models import Category, Household
from households.services.access import require_household_membership
from identity.models import User


@transaction.atomic
def create_category(
    *,
    household: Household,
    actor: User,
    name: str,
    color: str,
    sort_order: int,
    request_id: str,
) -> Category:
    require_household_membership(actor, household)
    category = Category(
        household=household,
        name=name.strip(),
        color=color.upper(),
        sort_order=sort_order,
    )
    category.full_clean()
    category.save()
    append_event(
        household=household,
        actor=actor,
        action="category.created",
        entity_type="category",
        entity_id=category.pk,
        request_id=request_id,
        after={
            "name": category.name,
            "color": category.color,
            "sort_order": category.sort_order,
        },
    )
    return category


@transaction.atomic
def update_category(
    *,
    category: Category,
    actor: User,
    name: str,
    color: str,
    sort_order: int,
    request_id: str,
) -> Category:
    locked = Category.objects.select_for_update().select_related("household").get(pk=category.pk)
    require_household_membership(actor, locked.household)
    if locked.is_archived:
        raise ValidationError("Archived categories cannot be edited.")
    before = {
        "name": locked.name,
        "color": locked.color,
        "sort_order": locked.sort_order,
    }
    locked.name = name.strip()
    locked.color = color.upper()
    locked.sort_order = sort_order
    locked.full_clean()
    locked.save(update_fields=("name", "color", "sort_order", "updated_at"))
    append_event(
        household=locked.household,
        actor=actor,
        action="category.updated",
        entity_type="category",
        entity_id=locked.pk,
        request_id=request_id,
        before=before,
        after={
            "name": locked.name,
            "color": locked.color,
            "sort_order": locked.sort_order,
        },
    )
    return locked


@transaction.atomic
def archive_category(
    *,
    category: Category,
    actor: User,
    request_id: str,
    reason: str,
) -> Category:
    locked = Category.objects.select_for_update().select_related("household").get(pk=category.pk)
    require_household_membership(actor, locked.household)
    if locked.is_archived:
        return locked
    if not reason.strip():
        raise ValidationError("Archiving a category requires a reason.")
    locked.is_archived = True
    locked.save(update_fields=("is_archived", "updated_at"))
    append_event(
        household=locked.household,
        actor=actor,
        action="category.archived",
        entity_type="category",
        entity_id=locked.pk,
        request_id=request_id,
        before={"is_archived": False},
        after={"is_archived": True},
        reason=reason.strip(),
    )
    return locked
