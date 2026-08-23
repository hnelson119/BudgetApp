from __future__ import annotations

from decimal import Decimal, InvalidOperation

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Sum

from audit.services import append_event
from households.models import Household
from households.services.access import require_household_membership
from identity.models import User
from periods.models import PayPeriod, PayPeriodClosingRevision
from reserves.models import ReserveEntry

_CENT = Decimal("0.01")


def reserve_balance(household: Household) -> Decimal:
    total = ReserveEntry.objects.filter(household=household).aggregate(total=Sum("amount"))["total"]
    return total or Decimal("0.00")


def _signed_money(value: Decimal) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ValidationError("Reserve amounts must use finite Decimal values.")
    try:
        normalized = value.quantize(_CENT)
    except InvalidOperation as error:
        raise ValidationError("Reserve amount is invalid.") from error
    if normalized != value:
        raise ValidationError("Reserve amounts may use at most two decimal places.")
    return normalized


@transaction.atomic
def record_period_closing_delta(
    *,
    household: Household,
    actor: User,
    closing_revision: PayPeriodClosingRevision,
    posting_period: PayPeriod,
    amount: Decimal,
    request_id: str,
    reason: str,
) -> ReserveEntry:
    require_household_membership(actor, household)
    revision = (
        PayPeriodClosingRevision.objects.select_for_update()
        .select_related("pay_period")
        .get(pk=closing_revision.pk)
    )
    posting = PayPeriod.objects.select_for_update().get(pk=posting_period.pk)
    if revision.pay_period.household_id != household.pk or posting.household_id != household.pk:
        raise ValidationError("Reserve entry periods must belong to the active household.")
    if ReserveEntry.objects.filter(closing_revision=revision).exists():
        raise ValidationError("This period closing revision already has a reserve entry.")
    normalized = _signed_money(amount)
    entry_type = (
        ReserveEntry.EntryType.PERIOD_CLOSE
        if revision.revision_number == 1
        else ReserveEntry.EntryType.PERIOD_CORRECTION
    )
    entry = ReserveEntry(
        household=household,
        source_period=revision.pay_period,
        posting_period=posting,
        closing_revision=revision,
        entry_type=entry_type,
        amount=normalized,
        reason=reason.strip(),
        created_by=actor,
    )
    entry.full_clean()
    entry._service_authorized = True  # type: ignore[attr-defined]
    entry.save()
    append_event(
        household=household,
        actor=actor,
        action="reserve.period_delta_recorded",
        entity_type="reserve_entry",
        entity_id=entry.pk,
        request_id=request_id,
        after={
            "source_period_id": entry.source_period_id,
            "posting_period_id": entry.posting_period_id,
            "closing_revision_id": revision.pk,
            "amount": entry.amount,
            "entry_type": entry.entry_type,
        },
        reason=reason.strip(),
    )
    return entry


@transaction.atomic
def allocate_reserve(
    *,
    household: Household,
    actor: User,
    posting_period: PayPeriod,
    amount: Decimal,
    allocation_label: str,
    request_id: str,
    reason: str = "",
) -> ReserveEntry:
    require_household_membership(actor, household)
    Household.objects.select_for_update().get(pk=household.pk)
    period = PayPeriod.objects.select_for_update().get(pk=posting_period.pk)
    if period.household_id != household.pk:
        raise ValidationError("The reserve allocation period belongs to another household.")
    if period.status == PayPeriod.Status.CLOSED:
        raise ValidationError("Reserve allocations cannot post to a closed paycheck period.")
    normalized = _signed_money(amount)
    if normalized <= 0:
        raise ValidationError("Reserve allocations must be positive amounts.")
    label = allocation_label.strip()
    if not label:
        raise ValidationError("Reserve allocations require a destination label.")
    if len(label) > 120:
        raise ValidationError("Reserve allocation labels may contain at most 120 characters.")
    available = reserve_balance(household)
    if normalized > available:
        raise ValidationError("The allocation cannot exceed the current Household Reserve.")
    entry = ReserveEntry(
        household=household,
        source_period=period,
        posting_period=period,
        entry_type=ReserveEntry.EntryType.EXPLICIT_ALLOCATION,
        amount=-normalized,
        allocation_label=label,
        reason=reason.strip(),
        created_by=actor,
    )
    entry.full_clean()
    entry._service_authorized = True  # type: ignore[attr-defined]
    entry.save()
    append_event(
        household=household,
        actor=actor,
        action="reserve.explicit_allocation_recorded",
        entity_type="reserve_entry",
        entity_id=entry.pk,
        request_id=request_id,
        after={
            "posting_period_id": period.pk,
            "amount": entry.amount,
            "allocation_label": entry.allocation_label,
            "remaining_reserve": available - normalized,
        },
        reason=reason.strip(),
    )
    return entry
