from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from zoneinfo import ZoneInfo

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Sum
from django.utils import timezone

from audit.services import append_event
from households.models import Category, Household
from households.services.access import require_household_membership
from identity.models import User
from ledger.models import FinancialAccount, JournalEntry, JournalPosting
from ledger.services import (
    record_debt_payment as record_ledger_debt_payment,
)
from ledger.services import (
    record_expense as record_ledger_expense,
)
from ledger.services import (
    record_expense_refund as record_ledger_expense_refund,
)
from ledger.services import (
    reverse_entry as reverse_ledger_entry,
)
from periods.models import PayPeriod
from reserves.models import CardPaymentReserveEntry
from spending.services.credit_cards import CardPaymentAllocation, allocate_card_payment


@dataclass(frozen=True, slots=True)
class CardPaymentResult:
    journal_entry: JournalEntry
    reserve_entry: CardPaymentReserveEntry
    allocation: CardPaymentAllocation


@dataclass(frozen=True, slots=True)
class CardPurchaseRefundResult:
    journal_entry: JournalEntry
    reserve_entry: CardPaymentReserveEntry
    refund_amount: Decimal
    reserve_released: Decimal
    remaining_refundable: Decimal


def _request_period(household: Household, effective_at: datetime) -> PayPeriod:
    if timezone.is_naive(effective_at):
        raise ValidationError("Card activity timestamps must include a timezone.")
    effective_date = timezone.localtime(
        effective_at,
        ZoneInfo(household.time_zone),
    ).date()
    period = PayPeriod.objects.filter(
        household=household,
        start_date__lte=effective_date,
        next_start_date__gt=effective_date,
    ).first()
    if period is None:
        raise ValidationError(
            "Card activity must fall inside a generated paycheck period before it can be saved."
        )
    return period


def _entry_amount(entry: JournalEntry) -> Decimal:
    total = entry.postings.filter(side=JournalPosting.Side.DEBIT).aggregate(total=Sum("amount"))[
        "total"
    ]
    return total or Decimal("0.00")


def _card_from_entry(entry: JournalEntry) -> FinancialAccount | None:
    posting = (
        entry.postings.select_related("financial_account")
        .filter(financial_account__isnull=False)
        .order_by("id")
        .first()
    )
    if posting is None or posting.financial_account is None:
        return None
    account = posting.financial_account
    if (
        account.account_type != FinancialAccount.AccountType.CREDIT_CARD
        or account.classification != FinancialAccount.Classification.LIABILITY
    ):
        return None
    return account


def _create_reserve_entry(
    *,
    household: Household,
    period: PayPeriod,
    card: FinancialAccount,
    journal_entry: JournalEntry,
    entry_type: str,
    amount: Decimal,
    actor: User,
    payment_amount: Decimal = Decimal("0.00"),
    reserve_settlement: Decimal = Decimal("0.00"),
    debt_payoff: Decimal = Decimal("0.00"),
    purchase_refund_amount: Decimal = Decimal("0.00"),
    neutral_correction: Decimal = Decimal("0.00"),
    reason: str = "",
) -> CardPaymentReserveEntry:
    reserve_entry = CardPaymentReserveEntry(
        household=household,
        pay_period=period,
        card_account=card,
        journal_entry=journal_entry,
        entry_type=entry_type,
        amount=amount,
        payment_amount=payment_amount,
        reserve_settlement=reserve_settlement,
        debt_payoff=debt_payoff,
        purchase_refund_amount=purchase_refund_amount,
        neutral_correction=neutral_correction,
        reason=reason.strip(),
        created_by=actor,
    )
    reserve_entry.full_clean()
    reserve_entry._service_authorized = True  # type: ignore[attr-defined]
    reserve_entry.save()
    return reserve_entry


def credit_card_payment_reserve(card: FinancialAccount) -> Decimal:
    if (
        card.account_type != FinancialAccount.AccountType.CREDIT_CARD
        or card.classification != FinancialAccount.Classification.LIABILITY
    ):
        raise ValidationError("A payment reserve is available only for a credit-card account.")
    total = CardPaymentReserveEntry.objects.filter(card_account=card).aggregate(
        total=Sum("amount")
    )["total"]
    return total or Decimal("0.00")


def household_card_payment_reserve(household: Household) -> Decimal:
    total = CardPaymentReserveEntry.objects.filter(household=household).aggregate(
        total=Sum("amount")
    )["total"]
    return total or Decimal("0.00")


def refundable_card_purchase_amount(entry: JournalEntry) -> Decimal:
    purchase = CardPaymentReserveEntry.objects.filter(
        journal_entry=entry,
        entry_type=CardPaymentReserveEntry.EntryType.PURCHASE,
    ).first()
    if purchase is None or JournalEntry.objects.filter(reversal_of=entry).exists():
        return Decimal("0.00")
    refunded = CardPaymentReserveEntry.objects.filter(
        journal_entry__adjustment_for=entry,
        entry_type=CardPaymentReserveEntry.EntryType.PURCHASE_REVERSAL,
    ).aggregate(total=Sum("purchase_refund_amount"))["total"] or Decimal("0.00")
    return max(purchase.amount - refunded, Decimal("0.00"))


def _active_purchase_reserve_target(card: FinancialAccount) -> Decimal:
    purchases = CardPaymentReserveEntry.objects.filter(
        card_account=card,
        entry_type=CardPaymentReserveEntry.EntryType.PURCHASE,
    ).aggregate(total=Sum("amount"))["total"] or Decimal("0.00")
    refunds = CardPaymentReserveEntry.objects.filter(
        card_account=card,
        entry_type=CardPaymentReserveEntry.EntryType.PURCHASE_REVERSAL,
    ).aggregate(total=Sum("purchase_refund_amount"))["total"] or Decimal("0.00")
    active_purchases = max(purchases - refunds, Decimal("0.00"))
    active_settlements = CardPaymentReserveEntry.objects.filter(
        card_account=card,
        entry_type=CardPaymentReserveEntry.EntryType.PAYMENT,
        journal_entry__reversal_entry__isnull=True,
    ).aggregate(total=Sum("reserve_settlement"))["total"] or Decimal("0.00")
    return max(active_purchases - active_settlements, Decimal("0.00"))


@transaction.atomic
def record_spending_expense(
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
    provenance: str = JournalEntry.Provenance.MANUAL,
    idempotency_key: str = "",
) -> JournalEntry:
    entry = record_ledger_expense(
        household=household,
        actor=actor,
        account=account,
        category=category,
        amount=amount,
        effective_at=effective_at,
        description=description,
        request_id=request_id,
        note=note,
        receipt_reference=receipt_reference,
        provenance=provenance,
        idempotency_key=idempotency_key,
    )
    card = _card_from_entry(entry)
    if card is None:
        return entry
    period = _request_period(household, entry.effective_at)
    reserve_entry = _create_reserve_entry(
        household=household,
        period=period,
        card=card,
        journal_entry=entry,
        entry_type=CardPaymentReserveEntry.EntryType.PURCHASE,
        amount=_entry_amount(entry),
        actor=actor,
    )
    append_event(
        household=household,
        actor=actor,
        action="card_reserve.purchase_reserved",
        entity_type="card_payment_reserve_entry",
        entity_id=reserve_entry.pk,
        request_id=request_id,
        after={
            "journal_entry_id": entry.pk,
            "card_account_id": card.pk,
            "pay_period_id": period.pk,
            "reserve_change": reserve_entry.amount,
            "reserve_balance": credit_card_payment_reserve(card),
        },
    )
    return entry


@transaction.atomic
def record_card_payment(
    *,
    household: Household,
    actor: User,
    source: FinancialAccount,
    card: FinancialAccount,
    amount: Decimal,
    effective_at: datetime,
    description: str,
    request_id: str,
    note: str = "",
    idempotency_key: str = "",
) -> CardPaymentResult:
    entry = record_ledger_debt_payment(
        household=household,
        actor=actor,
        source=source,
        liability=card,
        amount=amount,
        effective_at=effective_at,
        description=description,
        request_id=request_id,
        note=note,
        idempotency_key=idempotency_key,
    )
    locked_card = FinancialAccount.objects.select_for_update().get(pk=card.pk)
    if (
        locked_card.account_type != FinancialAccount.AccountType.CREDIT_CARD
        or locked_card.classification != FinancialAccount.Classification.LIABILITY
    ):
        raise ValidationError("Card payments require an active credit-card liability account.")
    opening_reserve = credit_card_payment_reserve(locked_card)
    if opening_reserve < 0:
        raise ValidationError("The card-payment reserve history is inconsistent.")
    allocation = allocate_card_payment(
        payment=amount,
        opening_payment_reserve=opening_reserve,
    )
    period = _request_period(household, entry.effective_at)
    reserve_entry = _create_reserve_entry(
        household=household,
        period=period,
        card=locked_card,
        journal_entry=entry,
        entry_type=CardPaymentReserveEntry.EntryType.PAYMENT,
        amount=-allocation.reserved_purchase_settlement,
        payment_amount=allocation.payment,
        reserve_settlement=allocation.reserved_purchase_settlement,
        debt_payoff=allocation.current_income_funded_debt_payoff,
        actor=actor,
    )
    append_event(
        household=household,
        actor=actor,
        action="card_reserve.payment_allocated",
        entity_type="card_payment_reserve_entry",
        entity_id=reserve_entry.pk,
        request_id=request_id,
        after={
            "journal_entry_id": entry.pk,
            "card_account_id": locked_card.pk,
            "pay_period_id": period.pk,
            "payment_amount": allocation.payment,
            "reserved_purchase_settlement": allocation.reserved_purchase_settlement,
            "current_income_funded_debt_payoff": (allocation.current_income_funded_debt_payoff),
            "reserve_balance": allocation.closing_payment_reserve,
        },
    )
    return CardPaymentResult(entry, reserve_entry, allocation)


@transaction.atomic
def record_card_purchase_refund(
    *,
    entry: JournalEntry,
    actor: User,
    amount: Decimal,
    effective_at: datetime,
    request_id: str,
    reason: str,
    idempotency_key: str = "",
) -> CardPurchaseRefundResult:
    purchase_reserve = (
        CardPaymentReserveEntry.objects.select_for_update()
        .select_related("household", "card_account", "journal_entry")
        .filter(
            journal_entry_id=entry.pk,
            entry_type=CardPaymentReserveEntry.EntryType.PURCHASE,
        )
        .first()
    )
    if purchase_reserve is None:
        raise ValidationError("Only a categorized credit-card purchase can receive this refund.")
    require_household_membership(actor, purchase_reserve.household)
    card = FinancialAccount.objects.select_for_update().get(pk=purchase_reserve.card_account_id)
    refund = record_ledger_expense_refund(
        original=purchase_reserve.journal_entry,
        actor=actor,
        amount=amount,
        effective_at=effective_at,
        description=f"Refund: {purchase_reserve.journal_entry.description}",
        request_id=request_id,
        reason=reason,
        idempotency_key=idempotency_key,
    )
    refund_amount = _entry_amount(refund)
    period = _request_period(purchase_reserve.household, refund.effective_at)
    available = credit_card_payment_reserve(card)
    if available < 0:
        raise ValidationError("The card-payment reserve history is inconsistent.")
    released = min(available, refund_amount)
    reserve_entry = _create_reserve_entry(
        household=purchase_reserve.household,
        period=period,
        card=card,
        journal_entry=refund,
        entry_type=CardPaymentReserveEntry.EntryType.PURCHASE_REVERSAL,
        amount=-released,
        purchase_refund_amount=refund_amount,
        actor=actor,
        reason=reason,
    )
    remaining = refundable_card_purchase_amount(purchase_reserve.journal_entry)
    append_event(
        household=purchase_reserve.household,
        actor=actor,
        action="card_reserve.purchase_refunded",
        entity_type="card_payment_reserve_entry",
        entity_id=reserve_entry.pk,
        request_id=request_id,
        after={
            "journal_entry_id": refund.pk,
            "original_journal_entry_id": purchase_reserve.journal_entry_id,
            "card_account_id": card.pk,
            "pay_period_id": period.pk,
            "refund_amount": refund_amount,
            "reserve_change": reserve_entry.amount,
            "reserve_balance": credit_card_payment_reserve(card),
            "remaining_refundable": remaining,
        },
        reason=reason.strip(),
    )
    return CardPurchaseRefundResult(
        refund,
        reserve_entry,
        refund_amount,
        released,
        remaining,
    )


@transaction.atomic
def reverse_spending_entry(
    *,
    entry: JournalEntry,
    actor: User,
    effective_at: datetime,
    request_id: str,
    reason: str,
) -> JournalEntry:
    original_reserve = (
        CardPaymentReserveEntry.objects.select_for_update()
        .filter(journal_entry_id=entry.pk)
        .first()
    )
    reversal = reverse_ledger_entry(
        entry=entry,
        actor=actor,
        effective_at=effective_at,
        request_id=request_id,
        reason=reason,
    )
    if original_reserve is None:
        return reversal
    require_household_membership(actor, original_reserve.household)
    card = FinancialAccount.objects.select_for_update().get(pk=original_reserve.card_account_id)
    period = _request_period(original_reserve.household, reversal.effective_at)
    if original_reserve.entry_type == CardPaymentReserveEntry.EntryType.PURCHASE:
        available = credit_card_payment_reserve(card)
        if available < 0:
            raise ValidationError("The card-payment reserve history is inconsistent.")
        released = min(available, original_reserve.amount)
        reserve_entry = _create_reserve_entry(
            household=original_reserve.household,
            period=period,
            card=card,
            journal_entry=reversal,
            entry_type=CardPaymentReserveEntry.EntryType.PURCHASE_REVERSAL,
            amount=-released,
            purchase_refund_amount=_entry_amount(reversal),
            actor=actor,
            reason=reason,
        )
    elif original_reserve.entry_type == CardPaymentReserveEntry.EntryType.PAYMENT:
        available = credit_card_payment_reserve(card)
        target = _active_purchase_reserve_target(card)
        restored = target - available
        if restored < 0 or restored > original_reserve.reserve_settlement:
            raise ValidationError("The card-payment reserve history is inconsistent.")
        reserve_entry = _create_reserve_entry(
            household=original_reserve.household,
            period=period,
            card=card,
            journal_entry=reversal,
            entry_type=CardPaymentReserveEntry.EntryType.PAYMENT_REVERSAL,
            amount=restored,
            payment_amount=original_reserve.payment_amount,
            reserve_settlement=restored,
            debt_payoff=original_reserve.debt_payoff,
            neutral_correction=original_reserve.reserve_settlement - restored,
            actor=actor,
            reason=reason,
        )
    else:
        raise ValidationError("A card-payment reserve correction cannot be reversed again.")
    append_event(
        household=original_reserve.household,
        actor=actor,
        action="card_reserve.entry_reversed",
        entity_type="card_payment_reserve_entry",
        entity_id=reserve_entry.pk,
        request_id=request_id,
        after={
            "journal_entry_id": reversal.pk,
            "original_reserve_entry_id": original_reserve.pk,
            "card_account_id": card.pk,
            "pay_period_id": period.pk,
            "reserve_change": reserve_entry.amount,
            "neutral_correction": reserve_entry.neutral_correction,
            "reserve_balance": credit_card_payment_reserve(card),
        },
        reason=reason.strip(),
    )
    return reversal
