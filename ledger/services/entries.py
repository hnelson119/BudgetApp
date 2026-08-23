from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Literal

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Sum
from django.utils import timezone

from audit.services import append_event
from households.models import Category, Household
from households.services.access import require_household_membership
from identity.models import User
from ledger.models import FinancialAccount, JournalEntry, JournalPosting

_CENT = Decimal("0.01")


@dataclass(frozen=True)
class PostingSpec:
    side: str
    amount: Decimal
    financial_account: FinancialAccount | None = None
    internal_account: str = ""


def _positive_amount(value: Decimal) -> Decimal:
    if not isinstance(value, Decimal):
        raise ValidationError("Ledger amounts must use Decimal values.")
    if not value.is_finite():
        raise ValidationError("Ledger amount is invalid.")
    try:
        normalized = value.quantize(_CENT)
    except InvalidOperation as error:
        raise ValidationError("Ledger amount is invalid.") from error
    if value != normalized or normalized <= 0:
        raise ValidationError("Ledger amounts must be positive and use at most two decimal places.")
    return normalized


def _active_account(account: FinancialAccount, household: Household) -> FinancialAccount:
    locked = FinancialAccount.objects.select_for_update().get(pk=account.pk)
    if locked.household_id != household.pk:
        raise ValidationError("Every financial account must belong to the active household.")
    if locked.is_archived:
        raise ValidationError("Archived financial accounts cannot receive new transactions.")
    return locked


def _active_category(category: Category, household: Household) -> Category:
    locked = Category.objects.select_for_update().get(pk=category.pk)
    if locked.household_id != household.pk:
        raise ValidationError("The category must belong to the active household.")
    if locked.is_archived:
        raise ValidationError("Archived categories cannot receive new expenses.")
    return locked


def _validate_postings(household: Household, postings: tuple[PostingSpec, ...]) -> None:
    if len(postings) < 2:
        raise ValidationError("A committed journal entry requires at least two postings.")
    debit_total = sum(
        (posting.amount for posting in postings if posting.side == JournalPosting.Side.DEBIT),
        Decimal("0.00"),
    )
    credit_total = sum(
        (posting.amount for posting in postings if posting.side == JournalPosting.Side.CREDIT),
        Decimal("0.00"),
    )
    if debit_total != credit_total:
        raise ValidationError("A committed journal entry must balance exactly.")
    for posting in postings:
        _positive_amount(posting.amount)
        has_financial = posting.financial_account is not None
        has_internal = bool(posting.internal_account)
        if has_financial == has_internal:
            raise ValidationError("Each posting must target exactly one ledger account.")
        if posting.side not in JournalPosting.Side.values:
            raise ValidationError("Journal posting side is invalid.")
        if posting.financial_account is not None:
            if posting.financial_account.household_id != household.pk:
                raise ValidationError("A posting account belongs to another household.")
        elif posting.internal_account not in JournalPosting.InternalAccount.values:
            raise ValidationError("Internal ledger account is invalid.")


def _commit_entry(
    *,
    household: Household,
    actor: User,
    effective_at: datetime,
    entry_type: str,
    description: str,
    postings: tuple[PostingSpec, ...],
    request_id: str,
    category: Category | None = None,
    note: str = "",
    receipt_reference: str = "",
    provenance: str = JournalEntry.Provenance.MANUAL,
    idempotency_key: str = "",
    reversal_of: JournalEntry | None = None,
    adjustment_for: JournalEntry | None = None,
    replacement_for: JournalEntry | None = None,
    audit_action: str = "ledger.entry_recorded",
    audit_reason: str = "",
) -> JournalEntry:
    require_household_membership(actor, household)
    if timezone.is_naive(effective_at):
        raise ValidationError("Journal entry timestamps must include a timezone.")
    if not description.strip():
        raise ValidationError("Journal entry description is required.")
    if (
        idempotency_key
        and JournalEntry.objects.filter(
            household=household,
            idempotency_key=idempotency_key,
        ).exists()
    ):
        raise ValidationError("The journal idempotency key has already been used.")
    _validate_postings(household, postings)
    entry = JournalEntry(
        household=household,
        effective_at=effective_at,
        entry_type=entry_type,
        description=description.strip(),
        category=category,
        provenance=provenance,
        note=note.strip(),
        receipt_reference=receipt_reference.strip(),
        idempotency_key=idempotency_key.strip(),
        reversal_of=reversal_of,
        adjustment_for=adjustment_for,
        replacement_for=replacement_for,
        created_by=actor,
        committed_at=timezone.now(),
    )
    entry.full_clean()
    entry._service_authorized = True  # type: ignore[attr-defined]
    entry.save()
    currency = household.currency.upper()
    for spec in postings:
        posting = JournalPosting(
            entry=entry,
            side=spec.side,
            amount=spec.amount,
            financial_account=spec.financial_account,
            internal_account=spec.internal_account,
            currency=currency,
        )
        posting.full_clean()
        posting._service_authorized = True  # type: ignore[attr-defined]
        posting.save()
    total = sum(
        (posting.amount for posting in postings if posting.side == JournalPosting.Side.DEBIT),
        Decimal("0.00"),
    )
    append_event(
        household=household,
        actor=actor,
        action=audit_action,
        entity_type="journal_entry",
        entity_id=entry.pk,
        request_id=request_id,
        after={
            "entry_type": entry.entry_type,
            "amount": total,
            "category_id": category.pk if category else None,
            "reversal_of_id": reversal_of.pk if reversal_of else None,
            "adjustment_for_id": adjustment_for.pk if adjustment_for else None,
        },
        reason=audit_reason,
    )
    return entry


@transaction.atomic
def record_income(
    *,
    household: Household,
    actor: User,
    destination: FinancialAccount,
    amount: Decimal,
    effective_at: datetime,
    description: str,
    request_id: str,
    note: str = "",
    idempotency_key: str = "",
) -> JournalEntry:
    destination = _active_account(destination, household)
    if destination.classification != FinancialAccount.Classification.ASSET:
        raise ValidationError("Income must be deposited into an asset account.")
    amount = _positive_amount(amount)
    return _commit_entry(
        household=household,
        actor=actor,
        effective_at=effective_at,
        entry_type=JournalEntry.EntryType.INCOME,
        description=description,
        note=note,
        idempotency_key=idempotency_key,
        request_id=request_id,
        postings=(
            PostingSpec(JournalPosting.Side.DEBIT, amount, financial_account=destination),
            PostingSpec(
                JournalPosting.Side.CREDIT,
                amount,
                internal_account=JournalPosting.InternalAccount.INCOME,
            ),
        ),
        audit_action="ledger.income_recorded",
    )


@transaction.atomic
def record_expense(
    *,
    household: Household,
    actor: User,
    account: FinancialAccount,
    category: Category,
    amount: Decimal,
    effective_at: datetime,
    description: str,
    request_id: str,
    note: str = "",
    receipt_reference: str = "",
    idempotency_key: str = "",
) -> JournalEntry:
    account = _active_account(account, household)
    category = _active_category(category, household)
    amount = _positive_amount(amount)
    return _commit_entry(
        household=household,
        actor=actor,
        effective_at=effective_at,
        entry_type=JournalEntry.EntryType.EXPENSE,
        description=description,
        category=category,
        note=note,
        receipt_reference=receipt_reference,
        idempotency_key=idempotency_key,
        request_id=request_id,
        postings=(
            PostingSpec(
                JournalPosting.Side.DEBIT,
                amount,
                internal_account=JournalPosting.InternalAccount.EXPENSE,
            ),
            PostingSpec(JournalPosting.Side.CREDIT, amount, financial_account=account),
        ),
        audit_action="ledger.expense_recorded",
    )


@transaction.atomic
def record_expense_refund(
    *,
    original: JournalEntry,
    actor: User,
    amount: Decimal,
    effective_at: datetime,
    description: str,
    request_id: str,
    reason: str,
    idempotency_key: str = "",
) -> JournalEntry:
    locked_original = (
        JournalEntry.objects.select_for_update()
        .select_related("household", "category")
        .get(pk=original.pk)
    )
    require_household_membership(actor, locked_original.household)
    if locked_original.entry_type != JournalEntry.EntryType.EXPENSE:
        raise ValidationError("Only an expense or purchase can receive a refund.")
    if locked_original.reversal_of_id is not None:
        raise ValidationError("A reversal entry cannot receive a refund.")
    if JournalEntry.objects.filter(reversal_of=locked_original).exists():
        raise ValidationError("A fully reversed expense cannot receive a refund.")
    if timezone.is_naive(effective_at):
        raise ValidationError("Journal entry timestamps must include a timezone.")
    if effective_at < locked_original.effective_at:
        raise ValidationError("A refund cannot be dated before the original purchase.")
    if not reason.strip():
        raise ValidationError("Expense refunds require a reason.")
    normalized = _positive_amount(amount)
    original_amount = locked_original.postings.filter(
        side=JournalPosting.Side.DEBIT,
        internal_account=JournalPosting.InternalAccount.EXPENSE,
    ).aggregate(total=Sum("amount"))["total"] or Decimal("0.00")
    refunded_amount = JournalPosting.objects.filter(
        entry__adjustment_for=locked_original,
        entry__entry_type=JournalEntry.EntryType.EXPENSE_REFUND,
        side=JournalPosting.Side.CREDIT,
        internal_account=JournalPosting.InternalAccount.EXPENSE,
    ).aggregate(total=Sum("amount"))["total"] or Decimal("0.00")
    remaining = original_amount - refunded_amount
    if normalized > remaining:
        raise ValidationError("Refunds cannot exceed the remaining purchase amount.")
    account_posting = (
        locked_original.postings.select_related("financial_account")
        .filter(financial_account__isnull=False)
        .first()
    )
    if account_posting is None or account_posting.financial_account is None:
        raise ValidationError("The original expense does not identify a financial account.")
    if locked_original.category is None:
        raise ValidationError("The original expense does not identify a spending category.")
    return _commit_entry(
        household=locked_original.household,
        actor=actor,
        effective_at=effective_at,
        entry_type=JournalEntry.EntryType.EXPENSE_REFUND,
        description=description,
        category=locked_original.category,
        note=reason,
        idempotency_key=idempotency_key,
        request_id=request_id,
        postings=(
            PostingSpec(
                JournalPosting.Side.DEBIT,
                normalized,
                financial_account=account_posting.financial_account,
            ),
            PostingSpec(
                JournalPosting.Side.CREDIT,
                normalized,
                internal_account=JournalPosting.InternalAccount.EXPENSE,
            ),
        ),
        adjustment_for=locked_original,
        audit_action="ledger.expense_refund_recorded",
        audit_reason=reason.strip(),
    )


def _record_account_movement(
    *,
    household: Household,
    actor: User,
    source: FinancialAccount,
    destination: FinancialAccount,
    amount: Decimal,
    effective_at: datetime,
    description: str,
    request_id: str,
    entry_type: str,
    audit_action: str,
    note: str,
    idempotency_key: str,
    source_classification: str,
    destination_classification: str,
) -> JournalEntry:
    source = _active_account(source, household)
    destination = _active_account(destination, household)
    if source.pk == destination.pk:
        raise ValidationError("Source and destination accounts must be different.")
    if source.classification != source_classification:
        raise ValidationError("The source account classification is invalid for this transaction.")
    if destination.classification != destination_classification:
        raise ValidationError(
            "The destination account classification is invalid for this transaction."
        )
    amount = _positive_amount(amount)
    return _commit_entry(
        household=household,
        actor=actor,
        effective_at=effective_at,
        entry_type=entry_type,
        description=description,
        note=note,
        idempotency_key=idempotency_key,
        request_id=request_id,
        postings=(
            PostingSpec(JournalPosting.Side.DEBIT, amount, financial_account=destination),
            PostingSpec(JournalPosting.Side.CREDIT, amount, financial_account=source),
        ),
        audit_action=audit_action,
    )


@transaction.atomic
def record_transfer(
    *,
    household: Household,
    actor: User,
    source: FinancialAccount,
    destination: FinancialAccount,
    amount: Decimal,
    effective_at: datetime,
    description: str,
    request_id: str,
    note: str = "",
    idempotency_key: str = "",
) -> JournalEntry:
    return _record_account_movement(
        household=household,
        actor=actor,
        source=source,
        destination=destination,
        amount=amount,
        effective_at=effective_at,
        description=description,
        request_id=request_id,
        entry_type=JournalEntry.EntryType.TRANSFER,
        audit_action="ledger.transfer_recorded",
        note=note,
        idempotency_key=idempotency_key,
        source_classification=FinancialAccount.Classification.ASSET,
        destination_classification=FinancialAccount.Classification.ASSET,
    )


@transaction.atomic
def record_debt_payment(
    *,
    household: Household,
    actor: User,
    source: FinancialAccount,
    liability: FinancialAccount,
    amount: Decimal,
    effective_at: datetime,
    description: str,
    request_id: str,
    note: str = "",
    idempotency_key: str = "",
) -> JournalEntry:
    return _record_account_movement(
        household=household,
        actor=actor,
        source=source,
        destination=liability,
        amount=amount,
        effective_at=effective_at,
        description=description,
        request_id=request_id,
        entry_type=JournalEntry.EntryType.DEBT_PAYMENT,
        audit_action="ledger.debt_payment_recorded",
        note=note,
        idempotency_key=idempotency_key,
        source_classification=FinancialAccount.Classification.ASSET,
        destination_classification=FinancialAccount.Classification.LIABILITY,
    )


@transaction.atomic
def record_goal_contribution(
    *,
    household: Household,
    actor: User,
    source: FinancialAccount,
    destination: FinancialAccount,
    amount: Decimal,
    effective_at: datetime,
    description: str,
    request_id: str,
    note: str = "",
    idempotency_key: str = "",
) -> JournalEntry:
    return _record_account_movement(
        household=household,
        actor=actor,
        source=source,
        destination=destination,
        amount=amount,
        effective_at=effective_at,
        description=description,
        request_id=request_id,
        entry_type=JournalEntry.EntryType.GOAL_CONTRIBUTION,
        audit_action="ledger.goal_contribution_recorded",
        note=note,
        idempotency_key=idempotency_key,
        source_classification=FinancialAccount.Classification.ASSET,
        destination_classification=FinancialAccount.Classification.ASSET,
    )


@transaction.atomic
def record_interest_or_fee(
    *,
    household: Household,
    actor: User,
    account: FinancialAccount,
    amount: Decimal,
    effective_at: datetime,
    description: str,
    request_id: str,
    note: str = "",
    idempotency_key: str = "",
) -> JournalEntry:
    account = _active_account(account, household)
    amount = _positive_amount(amount)
    return _commit_entry(
        household=household,
        actor=actor,
        effective_at=effective_at,
        entry_type=JournalEntry.EntryType.INTEREST_FEE,
        description=description,
        note=note,
        idempotency_key=idempotency_key,
        request_id=request_id,
        postings=(
            PostingSpec(
                JournalPosting.Side.DEBIT,
                amount,
                internal_account=JournalPosting.InternalAccount.EXPENSE,
            ),
            PostingSpec(JournalPosting.Side.CREDIT, amount, financial_account=account),
        ),
        audit_action="ledger.interest_fee_recorded",
    )


@transaction.atomic
def record_balance_adjustment(
    *,
    household: Household,
    actor: User,
    account: FinancialAccount,
    amount: Decimal,
    direction: Literal["increase", "decrease"],
    effective_at: datetime,
    description: str,
    request_id: str,
    reason: str,
    idempotency_key: str = "",
) -> JournalEntry:
    account = _active_account(account, household)
    amount = _positive_amount(amount)
    if direction not in ("increase", "decrease"):
        raise ValidationError("Balance adjustment direction is invalid.")
    if not reason.strip():
        raise ValidationError("Balance adjustments require a reason.")
    increases_with_debit = account.classification == FinancialAccount.Classification.ASSET
    account_side = (
        JournalPosting.Side.DEBIT
        if (direction == "increase") == increases_with_debit
        else JournalPosting.Side.CREDIT
    )
    offset_side = (
        JournalPosting.Side.CREDIT
        if account_side == JournalPosting.Side.DEBIT
        else JournalPosting.Side.DEBIT
    )
    return _commit_entry(
        household=household,
        actor=actor,
        effective_at=effective_at,
        entry_type=JournalEntry.EntryType.BALANCE_ADJUSTMENT,
        description=description,
        note=reason,
        idempotency_key=idempotency_key,
        request_id=request_id,
        postings=(
            PostingSpec(account_side, amount, financial_account=account),
            PostingSpec(
                offset_side,
                amount,
                internal_account=JournalPosting.InternalAccount.ADJUSTMENT,
            ),
        ),
        audit_action="ledger.balance_adjustment_recorded",
        audit_reason=reason.strip(),
    )


@transaction.atomic
def reverse_entry(
    *,
    entry: JournalEntry,
    actor: User,
    effective_at: datetime,
    request_id: str,
    reason: str,
) -> JournalEntry:
    original = (
        JournalEntry.objects.select_for_update()
        .select_related("household", "category")
        .get(pk=entry.pk)
    )
    require_household_membership(actor, original.household)
    if not reason.strip():
        raise ValidationError("Reversing a journal entry requires a reason.")
    if original.reversal_of_id is not None:
        raise ValidationError("A reversal entry cannot itself be reversed.")
    if original.entry_type == JournalEntry.EntryType.EXPENSE_REFUND:
        raise ValidationError("A refund entry cannot itself be reversed.")
    if JournalEntry.objects.filter(reversal_of=original).exists():
        raise ValidationError("The journal entry has already been reversed.")
    if JournalEntry.objects.filter(adjustment_for=original).exists():
        raise ValidationError("An expense with refunds must use the refund workflow.")
    postings = tuple(
        PostingSpec(
            JournalPosting.Side.CREDIT
            if posting.side == JournalPosting.Side.DEBIT
            else JournalPosting.Side.DEBIT,
            posting.amount,
            financial_account=posting.financial_account,
            internal_account=posting.internal_account,
        )
        for posting in original.postings.select_related("financial_account")
    )
    return _commit_entry(
        household=original.household,
        actor=actor,
        effective_at=effective_at,
        entry_type=original.entry_type,
        description=f"Reversal: {original.description}",
        category=original.category,
        note=reason,
        request_id=request_id,
        postings=postings,
        reversal_of=original,
        audit_action="ledger.entry_reversed",
        audit_reason=reason.strip(),
    )
