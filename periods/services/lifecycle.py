from __future__ import annotations

from datetime import date
from decimal import Decimal, InvalidOperation

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from audit.services import append_event
from households.models import Household
from households.services.access import require_household_membership
from identity.models import User
from periods.models import PayPeriod, PayPeriodClosingRevision
from reserves.services import record_period_closing_delta

_CENT = Decimal("0.01")


def _signed_money(value: Decimal) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ValidationError("Period closing amounts must use finite Decimal values.")
    try:
        normalized = value.quantize(_CENT)
    except InvalidOperation as error:
        raise ValidationError("Period closing amount is invalid.") from error
    if normalized != value:
        raise ValidationError("Period closing amounts may use at most two decimal places.")
    return normalized


@transaction.atomic
def refresh_period_states(
    *,
    household: Household,
    actor: User,
    today: date,
    request_id: str,
) -> tuple[int, int]:
    require_household_membership(actor, household)
    Household.objects.select_for_update().get(pk=household.pk)
    projected_to_open = list(
        PayPeriod.objects.select_for_update().filter(
            household=household,
            status=PayPeriod.Status.PROJECTED,
            start_date__lte=today,
            next_start_date__gt=today,
        )
    )
    open_to_review = list(
        PayPeriod.objects.select_for_update().filter(
            household=household,
            status=PayPeriod.Status.OPEN,
            next_start_date__lte=today,
        )
    )
    for period in projected_to_open:
        period.status = PayPeriod.Status.OPEN
        period.save(update_fields=("status", "updated_at"))
    for period in open_to_review:
        period.status = PayPeriod.Status.CLOSING_REVIEW
        period.save(update_fields=("status", "updated_at"))
    if projected_to_open or open_to_review:
        append_event(
            household=household,
            actor=actor,
            action="periods.states_refreshed",
            entity_type="pay_period_state_window",
            entity_id=today.isoformat(),
            request_id=request_id,
            after={
                "today": today,
                "opened_count": len(projected_to_open),
                "review_count": len(open_to_review),
            },
        )
    return len(projected_to_open), len(open_to_review)


@transaction.atomic
def close_period(
    *,
    pay_period: PayPeriod,
    actor: User,
    closing_surplus: Decimal,
    request_id: str,
    reason: str = "",
    posting_period: PayPeriod | None = None,
) -> PayPeriodClosingRevision:
    period = PayPeriod.objects.select_for_update().select_related("household").get(pk=pay_period.pk)
    require_household_membership(actor, period.household)
    if period.status not in (
        PayPeriod.Status.OPEN,
        PayPeriod.Status.CLOSING_REVIEW,
        PayPeriod.Status.REOPENED,
    ):
        raise ValidationError("This paycheck period cannot be closed from its current state.")
    normalized_surplus = _signed_money(closing_surplus)
    previous = period.closing_revisions.order_by("-revision_number").first()
    revision_number = 1 if previous is None else previous.revision_number + 1
    if previous is not None and period.status != PayPeriod.Status.REOPENED:
        raise ValidationError("A closed period must be reopened before it can be corrected.")
    if revision_number > 1 and not reason.strip():
        raise ValidationError("Correcting a closed period requires a reason.")
    reserve_delta = (
        normalized_surplus if previous is None else normalized_surplus - previous.closing_surplus
    )
    posting = period
    if revision_number > 1:
        if posting_period is None:
            raise ValidationError("A closed-period correction requires the current posting period.")
        posting = PayPeriod.objects.select_for_update().get(pk=posting_period.pk)
        if posting.household_id != period.household_id:
            raise ValidationError("The correction posting period belongs to another household.")
        if posting.status not in (PayPeriod.Status.OPEN, PayPeriod.Status.CLOSING_REVIEW):
            raise ValidationError("Closed-period corrections must post to a current active period.")

    revision = PayPeriodClosingRevision(
        pay_period=period,
        revision_number=revision_number,
        closing_surplus=normalized_surplus,
        reserve_delta=reserve_delta,
        reason=reason.strip(),
        created_by=actor,
    )
    revision.full_clean()
    revision._service_authorized = True  # type: ignore[attr-defined]
    revision.save()
    record_period_closing_delta(
        household=period.household,
        actor=actor,
        closing_revision=revision,
        posting_period=posting,
        amount=reserve_delta,
        request_id=request_id,
        reason=reason,
    )
    before_status = period.status
    period.status = PayPeriod.Status.CLOSED
    period.closed_at = timezone.now()
    period.save(update_fields=("status", "closed_at", "updated_at"))
    append_event(
        household=period.household,
        actor=actor,
        action="periods.period_closed" if revision_number == 1 else "periods.period_corrected",
        entity_type="pay_period",
        entity_id=period.pk,
        request_id=request_id,
        before={
            "status": before_status,
            "closing_surplus": previous.closing_surplus if previous else None,
        },
        after={
            "status": period.status,
            "closing_revision": revision_number,
            "closing_surplus": normalized_surplus,
            "reserve_delta": reserve_delta,
            "posting_period_id": posting.pk,
        },
        reason=reason.strip(),
    )
    return revision


@transaction.atomic
def reopen_period(
    *,
    pay_period: PayPeriod,
    actor: User,
    request_id: str,
    reason: str,
) -> PayPeriod:
    period = PayPeriod.objects.select_for_update().select_related("household").get(pk=pay_period.pk)
    require_household_membership(actor, period.household)
    if period.status != PayPeriod.Status.CLOSED:
        raise ValidationError("Only a closed paycheck period can be reopened.")
    if not reason.strip():
        raise ValidationError("Reopening a paycheck period requires a reason.")
    period.status = PayPeriod.Status.REOPENED
    period.save(update_fields=("status", "updated_at"))
    append_event(
        household=period.household,
        actor=actor,
        action="periods.period_reopened",
        entity_type="pay_period",
        entity_id=period.pk,
        request_id=request_id,
        before={"status": PayPeriod.Status.CLOSED},
        after={"status": period.status},
        reason=reason.strip(),
    )
    return period
