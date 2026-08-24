from __future__ import annotations

from decimal import Decimal, InvalidOperation
from zoneinfo import ZoneInfo

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Sum
from django.utils import timezone

from audit.services import append_event
from budgets.models import OccurrenceReconciliation
from households.services.access import require_household_membership
from identity.models import User
from ledger.models import JournalEntry, JournalPosting
from periods.models import PayPeriod
from reserves.models import CardPaymentReserveEntry
from schedules.models import Occurrence, RecurringSource

_CENT = Decimal("0.01")
_COMPATIBLE_ENTRY_TYPES: dict[str, set[str]] = {
    RecurringSource.Kind.INCOME: {JournalEntry.EntryType.INCOME},
    RecurringSource.Kind.FIXED_EXPENSE: {
        JournalEntry.EntryType.EXPENSE,
        JournalEntry.EntryType.INTEREST_FEE,
    },
    RecurringSource.Kind.DEBT_PAYMENT: {JournalEntry.EntryType.DEBT_PAYMENT},
    RecurringSource.Kind.GOAL_CONTRIBUTION: {
        JournalEntry.EntryType.GOAL_CONTRIBUTION,
        JournalEntry.EntryType.DEBT_PAYMENT,
    },
}


def _positive_money(value: Decimal) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ValidationError("Reconciliation amounts must use finite Decimal values.")
    try:
        normalized = value.quantize(_CENT)
    except InvalidOperation as error:
        raise ValidationError("Reconciliation amount is invalid.") from error
    if normalized != value or normalized <= 0:
        raise ValidationError("Reconciliation amounts must be positive with at most two decimals.")
    return normalized


def _entry_amount(entry: JournalEntry) -> Decimal:
    allocation = CardPaymentReserveEntry.objects.filter(journal_entry=entry).first()
    if allocation is not None and allocation.entry_type in (
        CardPaymentReserveEntry.EntryType.PAYMENT,
        CardPaymentReserveEntry.EntryType.PAYMENT_REVERSAL,
    ):
        return allocation.debt_payoff
    total = entry.postings.filter(side=JournalPosting.Side.DEBIT).aggregate(total=Sum("amount"))[
        "total"
    ]
    return total or Decimal("0.00")


@transaction.atomic
def reconcile_occurrence(
    *,
    occurrence: Occurrence,
    journal_entry: JournalEntry,
    amount: Decimal,
    actor: User,
    request_id: str,
) -> OccurrenceReconciliation:
    locked_occurrence = (
        Occurrence.objects.select_for_update(of=("self",))
        .select_related("source", "source__household", "pay_period")
        .get(pk=occurrence.pk)
    )
    require_household_membership(actor, locked_occurrence.source.household)
    entry = JournalEntry.objects.select_for_update().get(pk=journal_entry.pk)
    if entry.household_id != locked_occurrence.source.household_id:
        raise ValidationError("The journal entry belongs to another household.")
    if locked_occurrence.pay_period is None:
        raise ValidationError("The occurrence is not assigned to a paycheck period.")
    if locked_occurrence.pay_period.status == PayPeriod.Status.CLOSED:
        raise ValidationError("Reopen the closed paycheck period before reconciling it.")
    if locked_occurrence.status in (
        Occurrence.Status.CANCELLED,
        Occurrence.Status.SUPERSEDED,
    ):
        raise ValidationError("This occurrence state cannot be reconciled.")
    if entry.entry_type not in _COMPATIBLE_ENTRY_TYPES[locked_occurrence.source.kind]:
        raise ValidationError("The journal entry type does not match the scheduled item.")
    if entry.reversal_of_id is not None:
        raise ValidationError("Reversal entries use the correction workflow, not a new link.")
    if JournalEntry.objects.filter(reversal_of=entry).exists():
        raise ValidationError("A reversed journal entry cannot be reconciled.")
    normalized = _positive_money(amount)
    if OccurrenceReconciliation.objects.filter(
        occurrence=locked_occurrence,
        journal_entry=entry,
    ).exists():
        raise ValidationError("This journal entry is already linked to the occurrence.")
    entry_total = _entry_amount(entry)
    entry_applied = OccurrenceReconciliation.objects.filter(journal_entry=entry).aggregate(
        total=Sum("amount")
    )["total"] or Decimal("0.00")
    if entry_applied + normalized > entry_total:
        raise ValidationError("Reconciled amounts cannot exceed the journal entry total.")
    link = OccurrenceReconciliation(
        household=locked_occurrence.source.household,
        occurrence=locked_occurrence,
        journal_entry=entry,
        amount=normalized,
        created_by=actor,
    )
    link.full_clean()
    link._service_authorized = True  # type: ignore[attr-defined]
    link.save()
    occurrence_total = locked_occurrence.reconciliations.aggregate(total=Sum("amount"))[
        "total"
    ] or Decimal("0.00")
    locked_occurrence.actual_amount = occurrence_total
    locked_occurrence.actual_date = timezone.localtime(
        entry.effective_at,
        ZoneInfo(locked_occurrence.source.household.time_zone),
    ).date()
    locked_occurrence.status = Occurrence.Status.COMPLETED
    locked_occurrence.save(update_fields=("actual_amount", "actual_date", "status", "updated_at"))
    append_event(
        household=locked_occurrence.source.household,
        actor=actor,
        action="budget.occurrence_reconciled",
        entity_type="occurrence_reconciliation",
        entity_id=link.pk,
        request_id=request_id,
        after={
            "occurrence_id": locked_occurrence.pk,
            "journal_entry_id": entry.pk,
            "amount": link.amount,
            "occurrence_actual_total": occurrence_total,
        },
    )
    return link
