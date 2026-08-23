from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import date

from django.core.exceptions import ValidationError
from django.db import transaction

from audit.services import append_event
from households.models import Household
from households.services.access import require_household_membership
from identity.models import User
from periods.models import PayPeriod
from schedules.models import Occurrence, RecurringSource


@dataclass(frozen=True, slots=True)
class AssignmentChange:
    occurrence_id: uuid.UUID
    old_period_id: uuid.UUID
    new_period_id: uuid.UUID


@dataclass(frozen=True, slots=True)
class BoundaryChangePreview:
    occurrence_id: uuid.UUID
    period_id: uuid.UUID
    old_start_date: date
    new_start_date: date
    assignment_changes: tuple[AssignmentChange, ...]
    conflicts: tuple[str, ...]
    fingerprint: str


def _is_anchor(occurrence: Occurrence) -> bool:
    return (
        occurrence.source.kind == RecurringSource.Kind.INCOME
        and hasattr(occurrence.source, "income_detail")
        and occurrence.source.income_detail.starts_budget_period
    )


def preview_boundary_change(
    *,
    occurrence: Occurrence,
    actor: User,
    actual_date: date,
) -> BoundaryChangePreview:
    current_occurrence = Occurrence.objects.select_related(
        "source",
        "source__household",
        "source__income_detail",
        "pay_period",
    ).get(pk=occurrence.pk)
    require_household_membership(actor, current_occurrence.source.household)
    if not _is_anchor(current_occurrence):
        raise ValidationError("Only an anchor income occurrence can move a period boundary.")
    if current_occurrence.pay_period is None:
        raise ValidationError("The anchor occurrence is not assigned to a paycheck period.")
    period = current_occurrence.pay_period
    if period.start_date != current_occurrence.expected_date:
        raise ValidationError("The occurrence does not represent this period's expected boundary.")
    if actual_date == period.start_date:
        raise ValidationError("The actual date already matches the expected boundary.")
    if period.status in (PayPeriod.Status.CLOSED, PayPeriod.Status.REOPENED):
        raise ValidationError("Closed or reopened period boundaries require a historical workflow.")
    previous = PayPeriod.objects.filter(
        household=period.household,
        next_start_date=period.start_date,
    ).first()
    if previous is None:
        raise ValidationError("The preceding paycheck period is required to move this boundary.")
    if previous.status in (PayPeriod.Status.CLOSED, PayPeriod.Status.REOPENED):
        raise ValidationError("A boundary adjoining a closed period cannot move in this workflow.")
    if not previous.start_date < actual_date < period.next_start_date:
        raise ValidationError("The new boundary must remain between adjacent outer boundaries.")
    collision = PayPeriod.objects.filter(
        household=period.household,
        start_date=actual_date,
    ).exclude(pk=period.pk)
    if collision.exists():
        raise ValidationError("Another paycheck period already starts on the proposed date.")

    relevant = list(
        Occurrence.objects.filter(pay_period__in=(previous, period))
        .exclude(status__in=(Occurrence.Status.CANCELLED, Occurrence.Status.SUPERSEDED))
        .select_related("source", "source__income_detail")
    )
    changes: list[AssignmentChange] = []
    conflicts: list[str] = []
    for item in relevant:
        destination = period if item.expected_date >= actual_date else previous
        if item.pk == current_occurrence.pk:
            destination = period
        if item.pay_period_id == destination.pk:
            continue
        if item.pk != current_occurrence.pk and item.status != Occurrence.Status.SCHEDULED:
            conflicts.append(f"Occurrence {item.pk} has a protected period-specific state.")
            continue
        if item.pk != current_occurrence.pk and _is_anchor(item):
            conflicts.append(f"Anchor occurrence {item.pk} still supports the original boundary.")
            continue
        if item.pay_period_id is None:
            raise ValidationError("An active occurrence is missing its paycheck period.")
        changes.append(AssignmentChange(item.pk, item.pay_period_id, destination.pk))

    payload = {
        "occurrence_id": str(current_occurrence.pk),
        "period_id": str(period.pk),
        "previous_period_id": str(previous.pk),
        "old_start_date": period.start_date.isoformat(),
        "new_start_date": actual_date.isoformat(),
        "assignment_changes": [
            [str(item.occurrence_id), str(item.old_period_id), str(item.new_period_id)]
            for item in changes
        ],
        "conflicts": conflicts,
    }
    fingerprint = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return BoundaryChangePreview(
        current_occurrence.pk,
        period.pk,
        period.start_date,
        actual_date,
        tuple(changes),
        tuple(conflicts),
        fingerprint,
    )


@transaction.atomic
def apply_boundary_change(
    *,
    occurrence: Occurrence,
    actor: User,
    actual_date: date,
    expected_preview_fingerprint: str,
    request_id: str,
) -> BoundaryChangePreview:
    household = Household.objects.select_for_update().get(pk=occurrence.source.household_id)
    require_household_membership(actor, household)
    preview = preview_boundary_change(
        occurrence=occurrence,
        actor=actor,
        actual_date=actual_date,
    )
    if preview.fingerprint != expected_preview_fingerprint:
        raise ValidationError("The boundary preview is stale; preview it again before applying.")
    if preview.conflicts:
        raise ValidationError({"boundary": list(preview.conflicts)})
    period = PayPeriod.objects.select_for_update().get(pk=preview.period_id)
    previous = PayPeriod.objects.select_for_update().get(
        household=household,
        next_start_date=preview.old_start_date,
    )
    old_start = period.start_date

    def save_previous() -> None:
        previous.next_start_date = preview.new_start_date
        previous.boundary_revision += 1
        previous.full_clean()
        previous.save(update_fields=("next_start_date", "boundary_revision", "updated_at"))

    def save_period() -> None:
        period.start_date = preview.new_start_date
        period.boundary_source = PayPeriod.BoundarySource.ACTUAL
        period.boundary_revision += 1
        period.full_clean()
        period.save(
            update_fields=(
                "start_date",
                "boundary_source",
                "boundary_revision",
                "updated_at",
            )
        )

    if preview.new_start_date < old_start:
        save_previous()
        save_period()
    else:
        save_period()
        save_previous()

    for change in preview.assignment_changes:
        Occurrence.objects.filter(pk=change.occurrence_id).update(
            pay_period_id=change.new_period_id
        )

    append_event(
        household=household,
        actor=actor,
        action="periods.boundary_moved",
        entity_type="pay_period",
        entity_id=period.pk,
        request_id=request_id,
        before={"start_date": old_start},
        after={
            "start_date": period.start_date,
            "affected_occurrence_count": len(preview.assignment_changes),
        },
        reason="Confirmed actual anchor date differs from the projection.",
    )
    return preview
