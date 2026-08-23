from __future__ import annotations

from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Literal

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from audit.services import append_event
from households.services.access import require_household_membership
from identity.models import User
from periods.models import PayPeriod
from periods.services.boundaries import apply_boundary_change
from schedules.models import Occurrence, RecurringSource

_CENT = Decimal("0.01")


def _amount(value: Decimal) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ValidationError("Occurrence amounts must use finite Decimal values.")
    try:
        normalized = value.quantize(_CENT)
    except InvalidOperation as error:
        raise ValidationError("Occurrence amount is invalid.") from error
    if normalized != value or normalized < 0:
        raise ValidationError("Occurrence amounts must be nonnegative with at most two decimals.")
    return normalized


def _locked_occurrence(occurrence: Occurrence) -> Occurrence:
    return (
        Occurrence.objects.select_for_update(of=("self",))
        .select_related("source", "source__household", "source__income_detail", "pay_period")
        .get(pk=occurrence.pk)
    )


def _require_editable_period(occurrence: Occurrence) -> None:
    if (
        occurrence.pay_period is not None
        and occurrence.pay_period.status == PayPeriod.Status.CLOSED
    ):
        raise ValidationError("Reopen the closed paycheck period before changing its occurrences.")


@transaction.atomic
def move_occurrence(
    *,
    occurrence: Occurrence,
    target_period: PayPeriod,
    actor: User,
    request_id: str,
    reason: str,
) -> Occurrence:
    locked = _locked_occurrence(occurrence)
    require_household_membership(actor, locked.source.household)
    _require_editable_period(locked)
    target = PayPeriod.objects.select_for_update().get(pk=target_period.pk)
    if target.household_id != locked.source.household_id:
        raise ValidationError("The target period belongs to another household.")
    if target.status == PayPeriod.Status.CLOSED:
        raise ValidationError("Reopen the target paycheck period before moving an item into it.")
    if locked.pay_period_id is None:
        raise ValidationError("The occurrence is not assigned to a paycheck period.")
    if locked.pay_period_id == target.pk:
        raise ValidationError("The occurrence is already assigned to the target period.")
    if locked.original_pay_period_id is not None:
        raise ValidationError("An occurrence can be moved only once.")
    if locked.status not in (Occurrence.Status.SCHEDULED, Occurrence.Status.OVERRIDDEN):
        raise ValidationError("This occurrence state cannot be moved.")
    if not reason.strip():
        raise ValidationError("Moving an occurrence requires a reason.")
    old_period_id = locked.pay_period_id
    locked.original_pay_period_id = old_period_id
    locked.pay_period = target
    if locked.status == Occurrence.Status.SCHEDULED:
        locked.status = Occurrence.Status.MOVED
    locked.override_reason = reason.strip()
    locked.save(
        update_fields=(
            "original_pay_period",
            "pay_period",
            "status",
            "override_reason",
            "updated_at",
        )
    )
    append_event(
        household=locked.source.household,
        actor=actor,
        action="schedule.occurrence_moved",
        entity_type="occurrence",
        entity_id=locked.pk,
        request_id=request_id,
        before={"pay_period_id": old_period_id},
        after={"pay_period_id": target.pk, "original_pay_period_id": old_period_id},
        reason=reason.strip(),
    )
    return locked


@transaction.atomic
def override_occurrence(
    *,
    occurrence: Occurrence,
    actor: User,
    request_id: str,
    reason: str,
    planned_amount: Decimal | None = None,
    expected_date: date | None = None,
) -> Occurrence:
    locked = _locked_occurrence(occurrence)
    require_household_membership(actor, locked.source.household)
    _require_editable_period(locked)
    if locked.status not in (
        Occurrence.Status.SCHEDULED,
        Occurrence.Status.MOVED,
        Occurrence.Status.OVERRIDDEN,
    ):
        raise ValidationError("This occurrence state cannot be overridden.")
    if planned_amount is None and expected_date is None:
        raise ValidationError("An occurrence override must change an amount or date.")
    if not reason.strip():
        raise ValidationError("Overriding an occurrence requires a reason.")
    before = {
        "planned_amount": locked.planned_amount,
        "expected_date": locked.expected_date,
        "status": locked.status,
    }
    if planned_amount is not None:
        locked.planned_amount = _amount(planned_amount)
    if expected_date is not None:
        if locked.pay_period is None or not locked.pay_period.contains(expected_date):
            raise ValidationError(
                "A date override must remain in its paycheck period; "
                "move the item to change periods."
            )
        locked.expected_date = expected_date
    locked.status = Occurrence.Status.OVERRIDDEN
    locked.override_reason = reason.strip()
    locked.full_clean()
    locked.save(
        update_fields=(
            "planned_amount",
            "expected_date",
            "status",
            "override_reason",
            "updated_at",
        )
    )
    append_event(
        household=locked.source.household,
        actor=actor,
        action="schedule.occurrence_overridden",
        entity_type="occurrence",
        entity_id=locked.pk,
        request_id=request_id,
        before=before,
        after={
            "planned_amount": locked.planned_amount,
            "expected_date": locked.expected_date,
            "status": locked.status,
        },
        reason=reason.strip(),
    )
    return locked


@transaction.atomic
def cancel_occurrence(
    *,
    occurrence: Occurrence,
    actor: User,
    request_id: str,
    reason: str,
) -> Occurrence:
    locked = _locked_occurrence(occurrence)
    require_household_membership(actor, locked.source.household)
    _require_editable_period(locked)
    if locked.status in (
        Occurrence.Status.COMPLETED,
        Occurrence.Status.CORRECTED,
        Occurrence.Status.CANCELLED,
        Occurrence.Status.SUPERSEDED,
    ):
        raise ValidationError("This occurrence state cannot be cancelled.")
    if not reason.strip():
        raise ValidationError("Cancelling an occurrence requires a reason.")
    before_status = locked.status
    locked.status = Occurrence.Status.CANCELLED
    locked.cancellation_reason = reason.strip()
    locked.cancelled_at = timezone.now()
    locked.save(
        update_fields=(
            "status",
            "cancellation_reason",
            "cancelled_at",
            "updated_at",
        )
    )
    append_event(
        household=locked.source.household,
        actor=actor,
        action="schedule.occurrence_cancelled",
        entity_type="occurrence",
        entity_id=locked.pk,
        request_id=request_id,
        before={"status": before_status},
        after={"status": locked.status},
        reason=reason.strip(),
    )
    return locked


@transaction.atomic
def cancel_occurrence_and_future(
    *,
    occurrence: Occurrence,
    actor: User,
    request_id: str,
    reason: str,
) -> int:
    locked = _locked_occurrence(occurrence)
    require_household_membership(actor, locked.source.household)
    _require_editable_period(locked)
    if not reason.strip():
        raise ValidationError("Cancelling a recurring series requires a reason.")
    source = RecurringSource.objects.select_for_update().get(pk=locked.source_id)
    if source.is_archived:
        raise ValidationError("The recurring source is already archived.")
    now = timezone.now()
    source.archived_at = now
    source.archived_from = locked.nominal_date
    source.save(update_fields=("archived_at", "archived_from", "updated_at"))
    cancellable = source.occurrences.filter(
        nominal_date__gte=locked.nominal_date,
        status__in=(
            Occurrence.Status.SCHEDULED,
            Occurrence.Status.MOVED,
            Occurrence.Status.OVERRIDDEN,
        ),
    )
    cancelled_count = cancellable.update(
        status=Occurrence.Status.CANCELLED,
        cancellation_reason=reason.strip(),
        cancelled_at=now,
        updated_at=now,
    )
    append_event(
        household=locked.source.household,
        actor=actor,
        action="schedule.series_cancelled",
        entity_type="recurring_source",
        entity_id=source.pk,
        request_id=request_id,
        after={
            "archived_from": source.archived_from,
            "cancelled_occurrence_count": cancelled_count,
        },
        reason=reason.strip(),
    )
    return cancelled_count


@transaction.atomic
def complete_occurrence(
    *,
    occurrence: Occurrence,
    actor: User,
    actual_amount: Decimal,
    actual_date: date,
    request_id: str,
    boundary_decision: Literal["keep", "move"] | None = None,
    boundary_preview_fingerprint: str = "",
) -> Occurrence:
    locked = _locked_occurrence(occurrence)
    require_household_membership(actor, locked.source.household)
    _require_editable_period(locked)
    if locked.status not in (
        Occurrence.Status.SCHEDULED,
        Occurrence.Status.MOVED,
        Occurrence.Status.OVERRIDDEN,
    ):
        raise ValidationError("This occurrence state cannot be completed.")
    is_anchor = (
        locked.source.kind == RecurringSource.Kind.INCOME
        and hasattr(locked.source, "income_detail")
        and locked.source.income_detail.starts_budget_period
    )
    boundary_differs = is_anchor and actual_date != locked.expected_date
    if boundary_differs and boundary_decision not in ("keep", "move"):
        raise ValidationError("Choose whether the actual paycheck date moves the boundary.")
    if boundary_decision == "move":
        if not boundary_differs:
            raise ValidationError("The actual paycheck date does not require a boundary move.")
        apply_boundary_change(
            occurrence=locked,
            actor=actor,
            actual_date=actual_date,
            expected_preview_fingerprint=boundary_preview_fingerprint,
            request_id=request_id,
        )
        locked.refresh_from_db()
    elif boundary_decision == "keep" and not boundary_differs:
        raise ValidationError("A boundary decision is unnecessary when dates match.")

    locked.actual_amount = _amount(actual_amount)
    locked.actual_date = actual_date
    locked.status = Occurrence.Status.COMPLETED
    locked.save(update_fields=("actual_amount", "actual_date", "status", "updated_at"))
    append_event(
        household=locked.source.household,
        actor=actor,
        action="schedule.occurrence_completed",
        entity_type="occurrence",
        entity_id=locked.pk,
        request_id=request_id,
        after={
            "actual_amount": locked.actual_amount,
            "actual_date": locked.actual_date,
            "boundary_decision": boundary_decision,
        },
    )
    return locked
