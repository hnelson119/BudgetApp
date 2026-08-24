from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from unittest.mock import patch
from zoneinfo import ZoneInfo

import pytest
from django.core.exceptions import ValidationError

from audit.models import AuditEvent
from budgets.services.summary import build_period_summary
from households.models import Category, Household, HouseholdMembership
from households.services.categories import create_category
from identity.models import User
from ledger.models import FinancialAccount, JournalEntry, JournalPosting
from ledger.services import (
    calculated_account_balance,
    categorized_spending_total,
    create_financial_account,
    expense_total,
    record_balance_adjustment,
    record_interest_or_fee,
)
from periods.models import PayPeriod
from reserves.models import CardPaymentReserveEntry
from spending.services import (
    credit_card_payment_reserve,
    household_card_payment_reserve,
    record_card_payment,
    record_card_purchase_refund,
    record_spending_expense,
    refundable_card_purchase_amount,
    reverse_spending_entry,
)

TEST_PASSWORD = "card-reserve-test-password"  # pragma: allowlist secret
ZONE = ZoneInfo("America/New_York")


@dataclass(frozen=True, slots=True)
class CardContext:
    household: Household
    user: User
    first_period: PayPeriod
    second_period: PayPeriod
    checking: FinancialAccount
    card: FinancialAccount
    groceries: Category


@pytest.fixture
def card_context(db: object) -> CardContext:
    household = Household.objects.create(name="Card Reserve Household")
    user = User.objects.create_user(email="card@example.com", password=TEST_PASSWORD)
    HouseholdMembership.objects.create(household=household, user=user)
    first_period = PayPeriod.objects.create(
        household=household,
        start_date=date(2026, 8, 20),
        next_start_date=date(2026, 8, 27),
        status=PayPeriod.Status.OPEN,
        created_by=user,
    )
    second_period = PayPeriod.objects.create(
        household=household,
        start_date=date(2026, 8, 27),
        next_start_date=date(2026, 9, 3),
        status=PayPeriod.Status.PROJECTED,
        created_by=user,
    )
    checking = create_financial_account(
        household=household,
        actor=user,
        name="Checking",
        account_type=FinancialAccount.AccountType.CHECKING,
        classification=FinancialAccount.Classification.ASSET,
        request_id="card-context-checking",
    )
    card = create_financial_account(
        household=household,
        actor=user,
        name="Visa",
        account_type=FinancialAccount.AccountType.CREDIT_CARD,
        classification=FinancialAccount.Classification.LIABILITY,
        last_four="4242",
        request_id="card-context-visa",
    )
    groceries = create_category(
        household=household,
        actor=user,
        name="Groceries",
        color="#49D6A6",
        sort_order=10,
        request_id="card-context-groceries",
    )
    return CardContext(
        household,
        user,
        first_period,
        second_period,
        checking,
        card,
        groceries,
    )


def _purchase(context: CardContext, amount: str = "75.00") -> JournalEntry:
    return record_spending_expense(
        household=context.household,
        actor=context.user,
        account=context.card,
        category=context.groceries,
        amount=Decimal(amount),
        effective_at=datetime(2026, 8, 22, 12, tzinfo=ZONE),
        description="Visa groceries",
        request_id=f"card-purchase-{amount}",
    )


@pytest.mark.django_db
def test_golden_cases_e_and_f_persist_card_reserve_and_debt_split(
    card_context: CardContext,
) -> None:
    record_balance_adjustment(
        household=card_context.household,
        actor=card_context.user,
        account=card_context.card,
        amount=Decimal("100.00"),
        direction="increase",
        effective_at=datetime(2026, 8, 20, 10, tzinfo=ZONE),
        description="Existing revolving debt",
        request_id="card-existing-debt",
        reason="Opening statement balance",
    )
    purchase = _purchase(card_context)
    purchase_reserve = CardPaymentReserveEntry.objects.get(journal_entry=purchase)

    purchase_period_summary = build_period_summary(
        household=card_context.household,
        period=card_context.first_period,
        today=date(2026, 8, 22),
    )

    assert purchase_reserve.entry_type == CardPaymentReserveEntry.EntryType.PURCHASE
    assert purchase_reserve.amount == Decimal("75.00")
    assert purchase_reserve.pay_period == card_context.first_period
    assert purchase_period_summary.card_payment_reserve == Decimal("75.00")
    assert credit_card_payment_reserve(card_context.card) == Decimal("75.00")
    assert household_card_payment_reserve(card_context.household) == Decimal("75.00")
    assert categorized_spending_total(card_context.household) == Decimal("75.00")
    assert calculated_account_balance(card_context.checking) == Decimal("0.00")
    assert calculated_account_balance(card_context.card) == Decimal("175.00")

    payment = record_card_payment(
        household=card_context.household,
        actor=card_context.user,
        source=card_context.checking,
        card=card_context.card,
        amount=Decimal("175.00"),
        effective_at=datetime(2026, 8, 28, 9, tzinfo=ZONE),
        description="Visa payment",
        request_id="card-payment-175",
    )

    assert payment.allocation.reserved_purchase_settlement == Decimal("75.00")
    assert payment.allocation.current_income_funded_debt_payoff == Decimal("100.00")
    assert payment.allocation.closing_payment_reserve == Decimal("0.00")
    assert payment.reserve_entry.amount == Decimal("-75.00")
    assert payment.reserve_entry.pay_period == card_context.second_period
    assert credit_card_payment_reserve(card_context.card) == Decimal("0.00")
    assert categorized_spending_total(card_context.household) == Decimal("75.00")
    assert calculated_account_balance(card_context.checking) == Decimal("-175.00")
    assert calculated_account_balance(card_context.card) == Decimal("0.00")
    assert payment.journal_entry.category_id is None

    later_summary = build_period_summary(
        household=card_context.household,
        period=card_context.second_period,
        today=date(2026, 8, 28),
    )
    assert later_summary.actual_debt_payments == Decimal("100.00")
    assert later_summary.card_payment_reserve == Decimal("0.00")
    assert later_summary.actual_variable_spending == Decimal("0.00")
    assert AuditEvent.objects.filter(
        action="card_reserve.purchase_reserved",
        entity_id=str(purchase_reserve.pk),
    ).exists()
    assert AuditEvent.objects.filter(
        action="card_reserve.payment_allocated",
        entity_id=str(payment.reserve_entry.pk),
    ).exists()


@pytest.mark.django_db
def test_golden_case_g_interest_and_fees_do_not_change_card_reserve(
    card_context: CardContext,
) -> None:
    _purchase(card_context)
    record_interest_or_fee(
        household=card_context.household,
        actor=card_context.user,
        account=card_context.card,
        amount=Decimal("20.00"),
        effective_at=datetime(2026, 8, 23, 12, tzinfo=ZONE),
        description="Card interest",
        request_id="card-interest",
    )
    record_interest_or_fee(
        household=card_context.household,
        actor=card_context.user,
        account=card_context.card,
        amount=Decimal("5.00"),
        effective_at=datetime(2026, 8, 23, 13, tzinfo=ZONE),
        description="Late fee",
        request_id="card-fee",
    )

    assert credit_card_payment_reserve(card_context.card) == Decimal("75.00")
    assert categorized_spending_total(card_context.household) == Decimal("75.00")
    assert expense_total(card_context.household) == Decimal("100.00")


@pytest.mark.django_db
def test_multiple_partial_refunds_reduce_spending_liability_and_available_reserve(
    card_context: CardContext,
) -> None:
    purchase = _purchase(card_context)
    first_refund = record_card_purchase_refund(
        entry=purchase,
        actor=card_context.user,
        amount=Decimal("25.00"),
        effective_at=datetime(2026, 8, 23, 10, tzinfo=ZONE),
        request_id="card-partial-refund-25",
        reason="One grocery item was returned",
    )

    assert first_refund.journal_entry.entry_type == JournalEntry.EntryType.EXPENSE_REFUND
    assert first_refund.journal_entry.adjustment_for_id == purchase.pk
    assert first_refund.refund_amount == Decimal("25.00")
    assert first_refund.reserve_released == Decimal("25.00")
    assert first_refund.remaining_refundable == Decimal("50.00")
    assert first_refund.reserve_entry.amount == Decimal("-25.00")
    assert first_refund.reserve_entry.purchase_refund_amount == Decimal("25.00")
    assert credit_card_payment_reserve(card_context.card) == Decimal("50.00")
    assert calculated_account_balance(card_context.card) == Decimal("50.00")
    assert categorized_spending_total(card_context.household) == Decimal("50.00")
    assert expense_total(card_context.household) == Decimal("50.00")
    assert refundable_card_purchase_amount(purchase) == Decimal("50.00")

    summary = build_period_summary(
        household=card_context.household,
        period=card_context.first_period,
        today=date(2026, 8, 23),
    )
    assert summary.actual_variable_spending == Decimal("50.00")
    with pytest.raises(ValidationError, match="must use the refund workflow"):
        reverse_spending_entry(
            entry=purchase,
            actor=card_context.user,
            effective_at=datetime(2026, 8, 23, 11, tzinfo=ZONE),
            request_id="card-reject-full-reversal-after-partial",
            reason="Invalid full reversal after a partial refund",
        )

    second_refund = record_card_purchase_refund(
        entry=purchase,
        actor=card_context.user,
        amount=Decimal("50.00"),
        effective_at=datetime(2026, 8, 24, 10, tzinfo=ZONE),
        request_id="card-final-refund-50",
        reason="The remaining items were returned",
    )
    assert second_refund.remaining_refundable == Decimal("0.00")
    assert credit_card_payment_reserve(card_context.card) == Decimal("0.00")
    assert calculated_account_balance(card_context.card) == Decimal("0.00")
    assert categorized_spending_total(card_context.household) == Decimal("0.00")
    assert refundable_card_purchase_amount(purchase) == Decimal("0.00")
    with pytest.raises(ValidationError, match="cannot exceed"):
        record_card_purchase_refund(
            entry=purchase,
            actor=card_context.user,
            amount=Decimal("0.01"),
            effective_at=datetime(2026, 8, 24, 11, tzinfo=ZONE),
            request_id="card-over-refund",
            reason="No refundable amount remains",
        )
    assert AuditEvent.objects.filter(action="card_reserve.purchase_refunded").count() == 2


@pytest.mark.django_db
def test_partial_refund_after_payment_stays_neutral_when_payment_is_reversed(
    card_context: CardContext,
) -> None:
    purchase = _purchase(card_context)
    payment = record_card_payment(
        household=card_context.household,
        actor=card_context.user,
        source=card_context.checking,
        card=card_context.card,
        amount=Decimal("75.00"),
        effective_at=datetime(2026, 8, 23, 9, tzinfo=ZONE),
        description="Visa purchase settlement",
        request_id="card-payment-before-partial-refund",
    )
    refund = record_card_purchase_refund(
        entry=purchase,
        actor=card_context.user,
        amount=Decimal("30.00"),
        effective_at=datetime(2026, 8, 24, 10, tzinfo=ZONE),
        request_id="card-partial-refund-after-payment",
        reason="Part of the settled purchase was returned",
    )

    assert refund.reserve_released == Decimal("0.00")
    assert refund.reserve_entry.amount == Decimal("0.00")
    assert refund.reserve_entry.purchase_refund_amount == Decimal("30.00")
    assert calculated_account_balance(card_context.card) == Decimal("-30.00")
    assert categorized_spending_total(card_context.household) == Decimal("45.00")

    payment_reversal = reverse_spending_entry(
        entry=payment.journal_entry,
        actor=card_context.user,
        effective_at=datetime(2026, 8, 25, 9, tzinfo=ZONE),
        request_id="card-payment-reversal-after-partial-refund",
        reason="The card payment was returned",
    )
    correction = CardPaymentReserveEntry.objects.get(journal_entry=payment_reversal)
    assert correction.reserve_settlement == Decimal("45.00")
    assert correction.neutral_correction == Decimal("30.00")
    assert credit_card_payment_reserve(card_context.card) == Decimal("45.00")


@pytest.mark.django_db(transaction=True)
def test_partial_refund_rolls_back_when_reserve_audit_or_period_validation_fails(
    card_context: CardContext,
) -> None:
    purchase = _purchase(card_context)
    initial_entries = JournalEntry.objects.count()
    with (
        patch(
            "spending.services.transactions.append_event",
            side_effect=RuntimeError("refund reserve audit failed"),
        ),
        pytest.raises(RuntimeError, match="refund reserve audit failed"),
    ):
        record_card_purchase_refund(
            entry=purchase,
            actor=card_context.user,
            amount=Decimal("10.00"),
            effective_at=datetime(2026, 8, 23, 10, tzinfo=ZONE),
            request_id="card-refund-audit-rollback",
            reason="Exercise atomic audit rollback",
        )
    assert JournalEntry.objects.count() == initial_entries
    assert refundable_card_purchase_amount(purchase) == Decimal("75.00")

    with pytest.raises(ValidationError, match="generated paycheck period"):
        record_card_purchase_refund(
            entry=purchase,
            actor=card_context.user,
            amount=Decimal("10.00"),
            effective_at=datetime(2026, 9, 10, 10, tzinfo=ZONE),
            request_id="card-refund-period-rollback",
            reason="Refund falls outside generated periods",
        )
    assert JournalEntry.objects.count() == initial_entries
    assert refundable_card_purchase_amount(purchase) == Decimal("75.00")


@pytest.mark.django_db
def test_purchase_and_payment_reversals_correct_reserve_without_rewriting(
    card_context: CardContext,
) -> None:
    purchase = _purchase(card_context)
    purchase_reversal = reverse_spending_entry(
        entry=purchase,
        actor=card_context.user,
        effective_at=datetime(2026, 8, 24, 10, tzinfo=ZONE),
        request_id="card-purchase-refund",
        reason="Merchant issued a full refund",
    )
    refund_reserve = CardPaymentReserveEntry.objects.get(journal_entry=purchase_reversal)
    assert refund_reserve.entry_type == CardPaymentReserveEntry.EntryType.PURCHASE_REVERSAL
    assert refund_reserve.amount == Decimal("-75.00")
    assert credit_card_payment_reserve(card_context.card) == Decimal("0.00")
    assert categorized_spending_total(card_context.household) == Decimal("0.00")

    second_purchase = record_spending_expense(
        household=card_context.household,
        actor=card_context.user,
        account=card_context.card,
        category=card_context.groceries,
        amount=Decimal("50.00"),
        effective_at=datetime(2026, 8, 25, 12, tzinfo=ZONE),
        description="Second Visa purchase",
        request_id="card-second-purchase",
    )
    payment = record_card_payment(
        household=card_context.household,
        actor=card_context.user,
        source=card_context.checking,
        card=card_context.card,
        amount=Decimal("70.00"),
        effective_at=datetime(2026, 8, 25, 13, tzinfo=ZONE),
        description="Second Visa payment",
        request_id="card-second-payment",
    )
    assert payment.allocation.current_income_funded_debt_payoff == Decimal("20.00")
    assert credit_card_payment_reserve(card_context.card) == Decimal("0.00")
    payment_reversal = reverse_spending_entry(
        entry=payment.journal_entry,
        actor=card_context.user,
        effective_at=datetime(2026, 8, 26, 9, tzinfo=ZONE),
        request_id="card-payment-reversal",
        reason="Payment was returned",
    )
    restored = CardPaymentReserveEntry.objects.get(journal_entry=payment_reversal)
    assert restored.entry_type == CardPaymentReserveEntry.EntryType.PAYMENT_REVERSAL
    assert restored.amount == Decimal("50.00")
    assert credit_card_payment_reserve(card_context.card) == Decimal("50.00")

    reversal_summary = build_period_summary(
        household=card_context.household,
        period=card_context.first_period,
        today=date(2026, 8, 26),
    )
    assert reversal_summary.actual_debt_payments == Decimal("0.00")

    second_refund = reverse_spending_entry(
        entry=second_purchase,
        actor=card_context.user,
        effective_at=datetime(2026, 8, 26, 10, tzinfo=ZONE),
        request_id="card-second-refund",
        reason="Second purchase refunded",
    )
    assert CardPaymentReserveEntry.objects.get(journal_entry=second_refund).amount == Decimal(
        "-50.00"
    )
    assert credit_card_payment_reserve(card_context.card) == Decimal("0.00")


@pytest.mark.django_db
def test_payment_reversal_after_purchase_refund_does_not_restore_phantom_reserve(
    card_context: CardContext,
) -> None:
    purchase = _purchase(card_context)
    payment = record_card_payment(
        household=card_context.household,
        actor=card_context.user,
        source=card_context.checking,
        card=card_context.card,
        amount=Decimal("75.00"),
        effective_at=datetime(2026, 8, 23, 9, tzinfo=ZONE),
        description="Visa payment before refund",
        request_id="card-payment-before-refund",
    )
    reverse_spending_entry(
        entry=purchase,
        actor=card_context.user,
        effective_at=datetime(2026, 8, 24, 10, tzinfo=ZONE),
        request_id="card-refund-after-payment",
        reason="Merchant refunded the settled purchase",
    )

    payment_reversal = reverse_spending_entry(
        entry=payment.journal_entry,
        actor=card_context.user,
        effective_at=datetime(2026, 8, 25, 9, tzinfo=ZONE),
        request_id="card-payment-return-after-refund",
        reason="The bank returned the payment",
    )
    correction = CardPaymentReserveEntry.objects.get(journal_entry=payment_reversal)

    assert correction.reserve_settlement == Decimal("0.00")
    assert correction.debt_payoff == Decimal("0.00")
    assert correction.neutral_correction == Decimal("75.00")
    assert credit_card_payment_reserve(card_context.card) == Decimal("0.00")
    assert categorized_spending_total(card_context.household) == Decimal("0.00")


@pytest.mark.django_db(transaction=True)
def test_card_reserve_write_rolls_back_ledger_when_audit_append_fails(
    card_context: CardContext,
) -> None:
    initial_entries = JournalEntry.objects.count()
    with (
        patch(
            "spending.services.transactions.append_event",
            side_effect=RuntimeError("reserve audit failed"),
        ),
        pytest.raises(RuntimeError, match="reserve audit failed"),
    ):
        _purchase(card_context)

    assert JournalEntry.objects.count() == initial_entries
    assert CardPaymentReserveEntry.objects.count() == 0
    assert not AuditEvent.objects.filter(action="ledger.expense_recorded").exists()


@pytest.mark.django_db
def test_card_reserve_rejects_missing_period_invalid_account_and_mutation(
    card_context: CardContext,
) -> None:
    no_period_household = Household.objects.create(name="No card periods")
    no_period_user = User.objects.create_user(
        email="no-card-period@example.com",
        password=TEST_PASSWORD,
    )
    HouseholdMembership.objects.create(household=no_period_household, user=no_period_user)
    no_period_card = create_financial_account(
        household=no_period_household,
        actor=no_period_user,
        name="No period card",
        account_type=FinancialAccount.AccountType.CREDIT_CARD,
        classification=FinancialAccount.Classification.LIABILITY,
        request_id="no-period-card-account",
    )
    no_period_category = create_category(
        household=no_period_household,
        actor=no_period_user,
        name="No period category",
        color="#64748B",
        sort_order=0,
        request_id="no-period-card-category",
    )
    with pytest.raises(ValidationError, match="generated paycheck period"):
        record_spending_expense(
            household=no_period_household,
            actor=no_period_user,
            account=no_period_card,
            category=no_period_category,
            amount=Decimal("10.00"),
            effective_at=datetime(2026, 8, 22, 12, tzinfo=ZONE),
            description="No period purchase",
            request_id="no-period-card-purchase",
        )
    assert not JournalEntry.objects.filter(household=no_period_household).exists()

    with pytest.raises(ValidationError, match="only for a credit-card"):
        credit_card_payment_reserve(card_context.checking)

    other_liability = create_financial_account(
        household=card_context.household,
        actor=card_context.user,
        name="Other liability",
        account_type=FinancialAccount.AccountType.OTHER,
        classification=FinancialAccount.Classification.LIABILITY,
        request_id="card-other-liability",
    )
    entry_count = JournalEntry.objects.count()
    with pytest.raises(ValidationError, match="credit-card liability"):
        record_card_payment(
            household=card_context.household,
            actor=card_context.user,
            source=card_context.checking,
            card=other_liability,
            amount=Decimal("10.00"),
            effective_at=datetime(2026, 8, 22, 13, tzinfo=ZONE),
            description="Invalid card payment",
            request_id="card-invalid-payment",
        )
    assert JournalEntry.objects.count() == entry_count

    with pytest.raises(ValidationError, match="spending service"):
        CardPaymentReserveEntry.objects.create()

    purchase = _purchase(card_context)
    reserve_entry = CardPaymentReserveEntry.objects.get(journal_entry=purchase)
    reserve_entry.card_account = no_period_card
    with pytest.raises(ValidationError, match="another household"):
        reserve_entry.full_clean()
    reserve_entry.card_account = card_context.checking
    with pytest.raises(ValidationError, match="credit-card liability"):
        reserve_entry.full_clean()
    reserve_entry.card_account = card_context.card
    reserve_entry.amount = Decimal("1.00")
    with pytest.raises(ValidationError, match="spending service"):
        reserve_entry.save()
    reserve_entry._service_authorized = True  # type: ignore[attr-defined]
    with pytest.raises(ValidationError, match="cannot be updated"):
        reserve_entry.save()
    with pytest.raises(ValidationError, match="cannot be deleted"):
        reserve_entry.delete()
    with pytest.raises(ValidationError, match="cannot be updated"):
        CardPaymentReserveEntry.objects.filter(pk=reserve_entry.pk).update(amount=Decimal("1.00"))
    with pytest.raises(ValidationError, match="cannot be deleted"):
        CardPaymentReserveEntry.objects.filter(pk=reserve_entry.pk).delete()

    debits = sum(
        (
            posting.amount
            for posting in purchase.postings.all()
            if posting.side == JournalPosting.Side.DEBIT
        ),
        Decimal("0.00"),
    )
    assert debits == Decimal("75.00")


@pytest.mark.django_db
def test_negative_reserve_fail_safe_rolls_back_purchase_reversal(
    card_context: CardContext,
) -> None:
    purchase = _purchase(card_context)
    with (
        patch(
            "spending.services.transactions.credit_card_payment_reserve",
            return_value=Decimal("-1.00"),
        ),
        pytest.raises(ValidationError, match="history is inconsistent"),
    ):
        reverse_spending_entry(
            entry=purchase,
            actor=card_context.user,
            effective_at=datetime(2026, 8, 24, 10, tzinfo=ZONE),
            request_id="card-negative-reserve-reversal",
            reason="Exercise the corruption fail-safe",
        )

    assert not JournalEntry.objects.filter(reversal_of=purchase).exists()
    assert CardPaymentReserveEntry.objects.filter(journal_entry=purchase).count() == 1

    entry_count = JournalEntry.objects.count()
    with (
        patch(
            "spending.services.transactions.credit_card_payment_reserve",
            return_value=Decimal("-1.00"),
        ),
        pytest.raises(ValidationError, match="history is inconsistent"),
    ):
        record_card_payment(
            household=card_context.household,
            actor=card_context.user,
            source=card_context.checking,
            card=card_context.card,
            amount=Decimal("75.00"),
            effective_at=datetime(2026, 8, 24, 11, tzinfo=ZONE),
            description="Payment against corrupt reserve",
            request_id="card-negative-reserve-payment",
        )
    assert JournalEntry.objects.count() == entry_count

    payment = record_card_payment(
        household=card_context.household,
        actor=card_context.user,
        source=card_context.checking,
        card=card_context.card,
        amount=Decimal("75.00"),
        effective_at=datetime(2026, 8, 24, 12, tzinfo=ZONE),
        description="Valid payment before corrupt reversal",
        request_id="card-valid-payment-before-corrupt-reversal",
    )
    with (
        patch(
            "spending.services.transactions._active_purchase_reserve_target",
            return_value=Decimal("-1.00"),
        ),
        pytest.raises(ValidationError, match="history is inconsistent"),
    ):
        reverse_spending_entry(
            entry=payment.journal_entry,
            actor=card_context.user,
            effective_at=datetime(2026, 8, 24, 13, tzinfo=ZONE),
            request_id="card-corrupt-payment-reversal",
            reason="Exercise the payment-reversal fail-safe",
        )
    assert not JournalEntry.objects.filter(reversal_of=payment.journal_entry).exists()
