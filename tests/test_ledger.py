from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.utils import timezone

from audit.models import AuditEvent
from households.models import Category, Household, HouseholdMembership
from households.services.categories import archive_category, create_category, update_category
from identity.models import User
from ledger.models import BalanceSnapshot, FinancialAccount, JournalEntry, JournalPosting
from ledger.services import (
    account_reconciliation,
    archive_financial_account,
    calculated_account_balance,
    categorized_spending_total,
    create_financial_account,
    expense_total,
    record_balance_adjustment,
    record_balance_snapshot,
    record_debt_payment,
    record_expense,
    record_goal_contribution,
    record_income,
    record_interest_or_fee,
    record_transfer,
    reverse_entry,
    update_financial_account,
)
from ledger.services.entries import PostingSpec, _positive_amount, _validate_postings

TEST_PASSWORD = "correct-horse-battery-test"  # pragma: allowlist secret


@dataclass(frozen=True)
class LedgerContext:
    household: Household
    user: User
    outsider: User


@pytest.fixture
def ledger_context(db: object) -> LedgerContext:
    household = Household.objects.create(name="Nelson Household")
    user = User.objects.create_user(email="member@example.com", password=TEST_PASSWORD)
    outsider = User.objects.create_user(email="outsider@example.com", password=TEST_PASSWORD)
    HouseholdMembership.objects.create(household=household, user=user)
    return LedgerContext(household, user, outsider)


def make_account(
    context: LedgerContext,
    *,
    name: str,
    account_type: str = FinancialAccount.AccountType.CHECKING,
    classification: str = FinancialAccount.Classification.ASSET,
) -> FinancialAccount:
    return create_financial_account(
        household=context.household,
        actor=context.user,
        name=name,
        account_type=account_type,
        classification=classification,
        request_id=f"request-account-{name.lower().replace(' ', '-')}",
    )


def make_category(context: LedgerContext, *, name: str = "Groceries") -> Category:
    return create_category(
        household=context.household,
        actor=context.user,
        name=name,
        color="#34d399",
        sort_order=10,
        request_id=f"request-category-{name.lower().replace(' ', '-')}",
    )


@pytest.mark.django_db
def test_account_and_category_services_normalize_validate_and_audit(
    ledger_context: LedgerContext,
) -> None:
    category = create_category(
        household=ledger_context.household,
        actor=ledger_context.user,
        name="  Groceries  ",
        color="#34d399",
        sort_order=10,
        request_id="request-category-create",
    )
    account = create_financial_account(
        household=ledger_context.household,
        actor=ledger_context.user,
        name="  Household Checking  ",
        account_type=FinancialAccount.AccountType.CHECKING,
        classification=FinancialAccount.Classification.ASSET,
        last_four=" 1234 ",
        notes="  Joint account  ",
        request_id="request-account-create",
    )

    assert category.name == "Groceries"
    assert category.color == "#34D399"
    assert account.name == "Household Checking"
    assert account.last_four == "1234"
    assert account.notes == "Joint account"
    assert AuditEvent.objects.filter(action="category.created").exists()
    account_event = AuditEvent.objects.get(action="account.created")
    assert "last_four" not in account_event.after_payload

    with pytest.raises(ValidationError):
        make_category(ledger_context, name=" groceries ")
    category = update_category(
        category=category,
        actor=ledger_context.user,
        name="Food",
        color="#F59E0B",
        sort_order=20,
        request_id="request-category-update",
    )
    account = update_financial_account(
        account=account,
        actor=ledger_context.user,
        name="Joint Checking",
        last_four="1234",
        notes="Primary household account",
        request_id="request-account-update",
    )
    assert category.name == "Food"
    assert account.name == "Joint Checking"
    assert AuditEvent.objects.filter(action="category.updated").exists()
    assert AuditEvent.objects.filter(action="account.updated").exists()
    with pytest.raises(ValidationError):
        create_financial_account(
            household=ledger_context.household,
            actor=ledger_context.user,
            name="Invalid card",
            account_type=FinancialAccount.AccountType.CREDIT_CARD,
            classification=FinancialAccount.Classification.ASSET,
            request_id="request-invalid-account-type",
        )
    with pytest.raises(ValidationError):
        create_financial_account(
            household=ledger_context.household,
            actor=ledger_context.user,
            name="Too much identifier",
            account_type=FinancialAccount.AccountType.CHECKING,
            classification=FinancialAccount.Classification.ASSET,
            last_four="12345",
            request_id="request-invalid-last-four",
        )


@pytest.mark.django_db
def test_household_membership_is_required_for_account_and_category_mutations(
    ledger_context: LedgerContext,
) -> None:
    with pytest.raises(PermissionDenied):
        create_financial_account(
            household=ledger_context.household,
            actor=ledger_context.outsider,
            name="Hidden account",
            account_type=FinancialAccount.AccountType.CHECKING,
            classification=FinancialAccount.Classification.ASSET,
            request_id="request-outsider-account",
        )
    with pytest.raises(PermissionDenied):
        create_category(
            household=ledger_context.household,
            actor=ledger_context.outsider,
            name="Hidden category",
            color="#64748B",
            sort_order=0,
            request_id="request-outsider-category",
        )

    assert FinancialAccount.objects.count() == 0
    assert Category.objects.count() == 0
    assert AuditEvent.objects.count() == 0


@pytest.mark.django_db
def test_income_purchases_transfers_and_card_payments_have_correct_balances(
    ledger_context: LedgerContext,
) -> None:
    checking = make_account(ledger_context, name="Checking")
    savings = make_account(
        ledger_context,
        name="Savings",
        account_type=FinancialAccount.AccountType.SAVINGS,
    )
    card = make_account(
        ledger_context,
        name="Credit Card",
        account_type=FinancialAccount.AccountType.CREDIT_CARD,
        classification=FinancialAccount.Classification.LIABILITY,
    )
    groceries = make_category(ledger_context)
    effective_at = timezone.now()

    income = record_income(
        household=ledger_context.household,
        actor=ledger_context.user,
        destination=checking,
        amount=Decimal("1000.00"),
        effective_at=effective_at,
        description="Paycheck",
        request_id="request-income-1000",
    )
    cash_purchase = record_expense(
        household=ledger_context.household,
        actor=ledger_context.user,
        account=checking,
        category=groceries,
        amount=Decimal("100.00"),
        effective_at=effective_at,
        description="Grocery store",
        request_id="request-expense-cash",
    )
    card_purchase = record_expense(
        household=ledger_context.household,
        actor=ledger_context.user,
        account=card,
        category=groceries,
        amount=Decimal("50.00"),
        effective_at=effective_at,
        description="Card purchase",
        request_id="request-expense-card",
    )
    card_payment = record_debt_payment(
        household=ledger_context.household,
        actor=ledger_context.user,
        source=checking,
        liability=card,
        amount=Decimal("50.00"),
        effective_at=effective_at,
        description="Card payment",
        request_id="request-card-payment",
    )
    transfer = record_transfer(
        household=ledger_context.household,
        actor=ledger_context.user,
        source=checking,
        destination=savings,
        amount=Decimal("100.00"),
        effective_at=effective_at,
        description="Move to savings",
        request_id="request-transfer-savings",
    )
    goal_contribution = record_goal_contribution(
        household=ledger_context.household,
        actor=ledger_context.user,
        source=checking,
        destination=savings,
        amount=Decimal("25.00"),
        effective_at=effective_at,
        description="Emergency fund contribution",
        request_id="request-goal-contribution",
    )

    assert calculated_account_balance(checking) == Decimal("725.00")
    assert calculated_account_balance(savings) == Decimal("125.00")
    assert calculated_account_balance(card) == Decimal("0.00")
    assert categorized_spending_total(ledger_context.household) == Decimal("150.00")
    assert categorized_spending_total(
        ledger_context.household,
        category=groceries,
    ) == Decimal("150.00")
    assert expense_total(ledger_context.household) == Decimal("150.00")
    assert card_payment.category_id is None
    assert transfer.category_id is None

    for entry in (
        income,
        cash_purchase,
        card_purchase,
        card_payment,
        transfer,
        goal_contribution,
    ):
        debits = sum(
            (
                posting.amount
                for posting in entry.postings.all()
                if posting.side == JournalPosting.Side.DEBIT
            ),
            Decimal("0.00"),
        )
        credits = sum(
            (
                posting.amount
                for posting in entry.postings.all()
                if posting.side == JournalPosting.Side.CREDIT
            ),
            Decimal("0.00"),
        )
        assert debits == credits


@pytest.mark.django_db
def test_interest_reversal_and_adjustments_net_correctly(ledger_context: LedgerContext) -> None:
    checking = make_account(ledger_context, name="Checking")
    card = make_account(
        ledger_context,
        name="Card",
        account_type=FinancialAccount.AccountType.CREDIT_CARD,
        classification=FinancialAccount.Classification.LIABILITY,
    )
    groceries = make_category(ledger_context)
    effective_at = timezone.now()
    purchase = record_expense(
        household=ledger_context.household,
        actor=ledger_context.user,
        account=checking,
        category=groceries,
        amount=Decimal("25.00"),
        effective_at=effective_at,
        description="Mistaken purchase",
        request_id="request-mistaken-purchase",
    )
    record_interest_or_fee(
        household=ledger_context.household,
        actor=ledger_context.user,
        account=card,
        amount=Decimal("5.00"),
        effective_at=effective_at,
        description="Card interest",
        request_id="request-card-interest",
    )
    reversal = reverse_entry(
        entry=purchase,
        actor=ledger_context.user,
        effective_at=effective_at,
        request_id="request-purchase-reversal",
        reason="Entered against the wrong account",
    )
    record_balance_adjustment(
        household=ledger_context.household,
        actor=ledger_context.user,
        account=checking,
        amount=Decimal("10.00"),
        direction="increase",
        effective_at=effective_at,
        description="Opening balance correction",
        request_id="request-checking-adjustment",
        reason="Matched opening statement",
    )
    record_balance_adjustment(
        household=ledger_context.household,
        actor=ledger_context.user,
        account=card,
        amount=Decimal("2.00"),
        direction="increase",
        effective_at=effective_at,
        description="Liability correction",
        request_id="request-card-adjustment",
        reason="Matched card statement",
    )

    assert reversal.reversal_of_id == purchase.pk
    assert calculated_account_balance(checking) == Decimal("10.00")
    assert calculated_account_balance(card) == Decimal("7.00")
    assert categorized_spending_total(ledger_context.household) == Decimal("0.00")
    assert expense_total(ledger_context.household) == Decimal("5.00")
    with pytest.raises(ValidationError, match="already been reversed"):
        reverse_entry(
            entry=purchase,
            actor=ledger_context.user,
            effective_at=effective_at,
            request_id="request-second-reversal",
            reason="Duplicate reversal",
        )


@pytest.mark.django_db
def test_balance_snapshot_reports_latest_variance(ledger_context: LedgerContext) -> None:
    checking = make_account(ledger_context, name="Checking")
    effective_at = timezone.now()
    groceries = make_category(ledger_context)
    record_income(
        household=ledger_context.household,
        actor=ledger_context.user,
        destination=checking,
        amount=Decimal("900.00"),
        effective_at=effective_at,
        description="Opening amount",
        request_id="request-opening-income",
    )
    snapshot = record_balance_snapshot(
        household=ledger_context.household,
        actor=ledger_context.user,
        account=checking,
        observed_balance=Decimal("925.50"),
        observed_at=effective_at,
        request_id="request-balance-snapshot",
        note="Statement balance",
    )
    record_expense(
        household=ledger_context.household,
        actor=ledger_context.user,
        account=checking,
        category=groceries,
        amount=Decimal("100.00"),
        effective_at=effective_at + timedelta(hours=1),
        description="After snapshot",
        request_id="request-after-snapshot",
    )

    reconciliation = account_reconciliation(checking)
    assert reconciliation.snapshot == snapshot
    assert reconciliation.calculated_balance == Decimal("900.00")
    assert reconciliation.observed_balance == Decimal("925.50")
    assert reconciliation.variance == Decimal("25.50")
    assert calculated_account_balance(checking) == Decimal("800.00")
    snapshot_event = AuditEvent.objects.get(action="account.balance_observed")
    assert snapshot_event.after_payload["calculated_balance"] == "900.00"
    assert snapshot_event.after_payload["variance"] == "25.50"


@pytest.mark.django_db
@pytest.mark.parametrize(
    "invalid_amount",
    [
        Decimal("0.00"),
        Decimal("-1.00"),
        Decimal("1.001"),
        Decimal("NaN"),
        Decimal("Infinity"),
    ],
)
def test_invalid_ledger_amounts_do_not_commit(
    ledger_context: LedgerContext,
    invalid_amount: Decimal,
) -> None:
    checking = make_account(ledger_context, name="Checking")

    with pytest.raises(ValidationError):
        record_income(
            household=ledger_context.household,
            actor=ledger_context.user,
            destination=checking,
            amount=invalid_amount,
            effective_at=timezone.now(),
            description="Invalid amount",
            request_id="request-invalid-amount",
        )

    assert JournalEntry.objects.count() == 0
    assert JournalPosting.objects.count() == 0


@pytest.mark.django_db
def test_idempotency_key_and_stale_classification_cannot_bypass_invariants(
    ledger_context: LedgerContext,
) -> None:
    checking = make_account(ledger_context, name="Checking")
    card = make_account(
        ledger_context,
        name="Card",
        account_type=FinancialAccount.AccountType.CREDIT_CARD,
        classification=FinancialAccount.Classification.LIABILITY,
    )
    effective_at = timezone.now()
    record_income(
        household=ledger_context.household,
        actor=ledger_context.user,
        destination=checking,
        amount=Decimal("50.00"),
        effective_at=effective_at,
        description="Paycheck",
        request_id="request-idempotency-first",
        idempotency_key="paycheck-2026-08-20",
    )
    with pytest.raises(ValidationError, match="already been used"):
        record_income(
            household=ledger_context.household,
            actor=ledger_context.user,
            destination=checking,
            amount=Decimal("50.00"),
            effective_at=effective_at,
            description="Duplicate paycheck",
            request_id="request-idempotency-second",
            idempotency_key="paycheck-2026-08-20",
        )

    card.classification = FinancialAccount.Classification.ASSET
    with pytest.raises(ValidationError, match="destination account classification"):
        record_transfer(
            household=ledger_context.household,
            actor=ledger_context.user,
            source=checking,
            destination=card,
            amount=Decimal("10.00"),
            effective_at=effective_at,
            description="Invalid transfer",
            request_id="request-stale-account",
        )
    assert JournalEntry.objects.count() == 1


@pytest.mark.django_db
def test_cross_household_category_is_rejected(ledger_context: LedgerContext) -> None:
    checking = make_account(ledger_context, name="Checking")
    other_household = Household.objects.create(name="Other Household")
    HouseholdMembership.objects.create(household=other_household, user=ledger_context.user)
    other_category = create_category(
        household=other_household,
        actor=ledger_context.user,
        name="Other category",
        color="#64748B",
        sort_order=0,
        request_id="request-other-category",
    )

    with pytest.raises(ValidationError, match="active household"):
        record_expense(
            household=ledger_context.household,
            actor=ledger_context.user,
            account=checking,
            category=other_category,
            amount=Decimal("10.00"),
            effective_at=timezone.now(),
            description="Cross-household attempt",
            request_id="request-cross-household",
        )
    with pytest.raises(ValidationError, match="another household"):
        categorized_spending_total(ledger_context.household, category=other_category)

    assert JournalEntry.objects.count() == 0


@pytest.mark.django_db
def test_committed_ledger_rows_are_immutable(ledger_context: LedgerContext) -> None:
    checking = make_account(ledger_context, name="Checking")
    entry = record_income(
        household=ledger_context.household,
        actor=ledger_context.user,
        destination=checking,
        amount=Decimal("100.00"),
        effective_at=timezone.now(),
        description="Paycheck",
        request_id="request-immutable-entry",
    )
    posting = entry.postings.first()
    assert posting is not None

    entry.description = "Tampered"
    with pytest.raises(ValidationError, match="cannot be updated"):
        entry.save()
    with pytest.raises(ValidationError, match="cannot be deleted"):
        entry.delete()
    with pytest.raises(ValidationError, match="cannot be updated"):
        JournalPosting.objects.filter(pk=posting.pk).update(amount=Decimal("1.00"))
    with pytest.raises(ValidationError, match="cannot be deleted"):
        JournalPosting.objects.filter(pk=posting.pk).delete()
    with pytest.raises(ValidationError, match="must use a ledger service"):
        BalanceSnapshot.objects.create()


@pytest.mark.django_db(transaction=True)
def test_ledger_change_rolls_back_when_audit_append_fails(
    ledger_context: LedgerContext,
) -> None:
    checking = make_account(ledger_context, name="Checking")

    with (
        patch("ledger.services.entries.append_event", side_effect=RuntimeError("audit failed")),
        pytest.raises(RuntimeError, match="audit failed"),
    ):
        record_income(
            household=ledger_context.household,
            actor=ledger_context.user,
            destination=checking,
            amount=Decimal("100.00"),
            effective_at=timezone.now(),
            description="Paycheck",
            request_id="request-audit-failure",
        )

    assert JournalEntry.objects.count() == 0
    assert JournalPosting.objects.count() == 0
    assert AuditEvent.objects.filter(action="ledger.income_recorded").count() == 0


@pytest.mark.django_db
def test_archived_accounts_and_categories_retain_history_but_reject_new_activity(
    ledger_context: LedgerContext,
) -> None:
    checking = make_account(ledger_context, name="Checking")
    groceries = make_category(ledger_context)
    effective_at = timezone.now()
    recorded = record_expense(
        household=ledger_context.household,
        actor=ledger_context.user,
        account=checking,
        category=groceries,
        amount=Decimal("10.00"),
        effective_at=effective_at,
        description="Before archive",
        request_id="request-before-archive",
    )
    with pytest.raises(ValidationError, match="requires a reason"):
        archive_category(
            category=groceries,
            actor=ledger_context.user,
            request_id="request-category-archive-without-reason",
            reason="   ",
        )
    with pytest.raises(ValidationError, match="requires a reason"):
        archive_financial_account(
            account=checking,
            actor=ledger_context.user,
            request_id="request-account-archive-without-reason",
            reason="   ",
        )
    archive_category(
        category=groceries,
        actor=ledger_context.user,
        request_id="request-category-archive",
        reason="No longer used",
    )
    archive_financial_account(
        account=checking,
        actor=ledger_context.user,
        request_id="request-account-archive",
        reason="Account closed",
    )
    assert (
        archive_category(
            category=groceries,
            actor=ledger_context.user,
            request_id="request-category-already-archived",
            reason="Already archived",
        ).pk
        == groceries.pk
    )
    assert (
        archive_financial_account(
            account=checking,
            actor=ledger_context.user,
            request_id="request-account-already-archived",
            reason="Already archived",
        ).pk
        == checking.pk
    )

    with pytest.raises(ValidationError, match="Archived financial accounts"):
        update_financial_account(
            account=checking,
            actor=ledger_context.user,
            name="Renamed",
            last_four="",
            notes="",
            request_id="request-archived-account-update",
        )
    with pytest.raises(ValidationError, match="Archived categories"):
        update_category(
            category=groceries,
            actor=ledger_context.user,
            name="Renamed",
            color="#64748B",
            sort_order=0,
            request_id="request-archived-category-update",
        )
    with pytest.raises(ValidationError, match="Archived financial accounts"):
        record_balance_snapshot(
            household=ledger_context.household,
            actor=ledger_context.user,
            account=checking,
            observed_balance=Decimal("10.00"),
            observed_at=effective_at,
            request_id="request-archived-snapshot",
        )

    assert JournalEntry.objects.filter(pk=recorded.pk).exists()
    assert recorded.postings.count() == 2


@pytest.mark.django_db
def test_ledger_posting_validation_rejects_malformed_and_cross_household_specs(
    ledger_context: LedgerContext,
) -> None:
    checking = make_account(ledger_context, name="Posting checking")
    other_household = Household.objects.create(name="Posting other household")
    HouseholdMembership.objects.create(household=other_household, user=ledger_context.user)
    other_account = create_financial_account(
        household=other_household,
        actor=ledger_context.user,
        name="Posting other checking",
        account_type=FinancialAccount.AccountType.CHECKING,
        classification=FinancialAccount.Classification.ASSET,
        request_id="request-posting-other-account",
    )

    with pytest.raises(ValidationError, match="Decimal values"):
        _positive_amount("1.00")  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="at least two"):
        _validate_postings(
            ledger_context.household,
            (PostingSpec(JournalPosting.Side.DEBIT, Decimal("1.00"), checking),),
        )
    with pytest.raises(ValidationError, match="balance exactly"):
        _validate_postings(
            ledger_context.household,
            (
                PostingSpec(JournalPosting.Side.DEBIT, Decimal("2.00"), checking),
                PostingSpec(
                    JournalPosting.Side.CREDIT,
                    Decimal("1.00"),
                    internal_account=JournalPosting.InternalAccount.INCOME,
                ),
            ),
        )
    with pytest.raises(ValidationError, match="exactly one"):
        _validate_postings(
            ledger_context.household,
            (
                PostingSpec(
                    JournalPosting.Side.DEBIT,
                    Decimal("1.00"),
                    checking,
                    JournalPosting.InternalAccount.INCOME,
                ),
                PostingSpec(
                    JournalPosting.Side.CREDIT,
                    Decimal("1.00"),
                    internal_account=JournalPosting.InternalAccount.INCOME,
                ),
            ),
        )
    with pytest.raises(ValidationError, match="side is invalid"):
        _validate_postings(
            ledger_context.household,
            (
                PostingSpec("invalid", Decimal("1.00"), checking),
                PostingSpec(
                    JournalPosting.Side.DEBIT,
                    Decimal("1.00"),
                    internal_account=JournalPosting.InternalAccount.EXPENSE,
                ),
                PostingSpec(
                    JournalPosting.Side.CREDIT,
                    Decimal("1.00"),
                    internal_account=JournalPosting.InternalAccount.INCOME,
                ),
            ),
        )
    with pytest.raises(ValidationError, match="another household"):
        _validate_postings(
            ledger_context.household,
            (
                PostingSpec(JournalPosting.Side.DEBIT, Decimal("1.00"), other_account),
                PostingSpec(
                    JournalPosting.Side.CREDIT,
                    Decimal("1.00"),
                    internal_account=JournalPosting.InternalAccount.INCOME,
                ),
            ),
        )
    with pytest.raises(ValidationError, match="Internal ledger account"):
        _validate_postings(
            ledger_context.household,
            (
                PostingSpec(JournalPosting.Side.DEBIT, Decimal("1.00"), checking),
                PostingSpec(
                    JournalPosting.Side.CREDIT,
                    Decimal("1.00"),
                    internal_account="invalid",
                ),
            ),
        )


@pytest.mark.django_db
def test_ledger_services_reject_invalid_accounts_metadata_and_movements(
    ledger_context: LedgerContext,
) -> None:
    checking = make_account(ledger_context, name="Validation checking")
    savings = make_account(
        ledger_context,
        name="Validation savings",
        account_type=FinancialAccount.AccountType.SAVINGS,
    )
    card = make_account(
        ledger_context,
        name="Validation card",
        account_type=FinancialAccount.AccountType.CREDIT_CARD,
        classification=FinancialAccount.Classification.LIABILITY,
    )
    category = make_category(ledger_context, name="Validation category")
    effective_at = timezone.now()

    with pytest.raises(ValidationError, match="asset account"):
        record_income(
            household=ledger_context.household,
            actor=ledger_context.user,
            destination=card,
            amount=Decimal("10.00"),
            effective_at=effective_at,
            description="Invalid income destination",
            request_id="request-invalid-income-destination",
        )
    with pytest.raises(ValidationError, match="include a timezone"):
        record_income(
            household=ledger_context.household,
            actor=ledger_context.user,
            destination=checking,
            amount=Decimal("10.00"),
            effective_at=effective_at.replace(tzinfo=None),
            description="Naive income",
            request_id="request-naive-income",
        )
    with pytest.raises(ValidationError, match="description is required"):
        record_income(
            household=ledger_context.household,
            actor=ledger_context.user,
            destination=checking,
            amount=Decimal("10.00"),
            effective_at=effective_at,
            description="   ",
            request_id="request-blank-description",
        )
    with pytest.raises(ValidationError, match="must be different"):
        record_transfer(
            household=ledger_context.household,
            actor=ledger_context.user,
            source=checking,
            destination=checking,
            amount=Decimal("10.00"),
            effective_at=effective_at,
            description="Same account transfer",
            request_id="request-same-account-transfer",
        )
    with pytest.raises(ValidationError, match="source account classification"):
        record_transfer(
            household=ledger_context.household,
            actor=ledger_context.user,
            source=card,
            destination=savings,
            amount=Decimal("10.00"),
            effective_at=effective_at,
            description="Liability source transfer",
            request_id="request-liability-source-transfer",
        )
    with pytest.raises(ValidationError, match="direction is invalid"):
        record_balance_adjustment(
            household=ledger_context.household,
            actor=ledger_context.user,
            account=checking,
            amount=Decimal("10.00"),
            direction="sideways",  # type: ignore[arg-type]
            effective_at=effective_at,
            description="Invalid direction",
            request_id="request-invalid-adjustment-direction",
            reason="Testing validation",
        )
    with pytest.raises(ValidationError, match="require a reason"):
        record_balance_adjustment(
            household=ledger_context.household,
            actor=ledger_context.user,
            account=checking,
            amount=Decimal("10.00"),
            direction="increase",
            effective_at=effective_at,
            description="Missing reason",
            request_id="request-blank-adjustment-reason",
            reason="   ",
        )

    entry = record_expense(
        household=ledger_context.household,
        actor=ledger_context.user,
        account=checking,
        category=category,
        amount=Decimal("10.00"),
        effective_at=effective_at,
        description="Reversal validation",
        request_id="request-reversal-validation-entry",
    )
    with pytest.raises(ValidationError, match="requires a reason"):
        reverse_entry(
            entry=entry,
            actor=ledger_context.user,
            effective_at=effective_at,
            request_id="request-blank-reversal-reason",
            reason="   ",
        )


@pytest.mark.django_db
def test_ledger_services_reject_cross_household_and_archived_objects(
    ledger_context: LedgerContext,
) -> None:
    checking = make_account(ledger_context, name="Archive checking")
    active_checking = make_account(ledger_context, name="Active checking")
    category = make_category(ledger_context, name="Archive category")
    other_household = Household.objects.create(name="Ledger object other household")
    HouseholdMembership.objects.create(household=other_household, user=ledger_context.user)
    other_account = create_financial_account(
        household=other_household,
        actor=ledger_context.user,
        name="Other household checking",
        account_type=FinancialAccount.AccountType.CHECKING,
        classification=FinancialAccount.Classification.ASSET,
        request_id="request-other-household-checking",
    )

    with pytest.raises(ValidationError, match="active household"):
        record_income(
            household=ledger_context.household,
            actor=ledger_context.user,
            destination=other_account,
            amount=Decimal("10.00"),
            effective_at=timezone.now(),
            description="Cross-household income",
            request_id="request-cross-household-income",
        )

    archive_financial_account(
        account=checking,
        actor=ledger_context.user,
        request_id="request-archive-validation-checking",
        reason="Account closed",
    )
    with pytest.raises(ValidationError, match="Archived financial accounts"):
        record_income(
            household=ledger_context.household,
            actor=ledger_context.user,
            destination=checking,
            amount=Decimal("10.00"),
            effective_at=timezone.now(),
            description="Archived account income",
            request_id="request-archived-account-income",
        )

    archive_category(
        category=category,
        actor=ledger_context.user,
        request_id="request-archive-validation-category",
        reason="Category retired",
    )
    with pytest.raises(ValidationError, match="Archived categories"):
        record_expense(
            household=ledger_context.household,
            actor=ledger_context.user,
            account=active_checking,
            category=category,
            amount=Decimal("10.00"),
            effective_at=timezone.now(),
            description="Archived category expense",
            request_id="request-archived-category-expense",
        )


@pytest.mark.django_db
def test_balance_queries_and_snapshots_reject_invalid_inputs(
    ledger_context: LedgerContext,
) -> None:
    checking = make_account(ledger_context, name="Snapshot checking")
    other_household = Household.objects.create(name="Snapshot other household")
    HouseholdMembership.objects.create(household=other_household, user=ledger_context.user)
    other_account = create_financial_account(
        household=other_household,
        actor=ledger_context.user,
        name="Snapshot other checking",
        account_type=FinancialAccount.AccountType.CHECKING,
        classification=FinancialAccount.Classification.ASSET,
        request_id="request-snapshot-other-account",
    )
    observed_at = timezone.now()

    assert account_reconciliation(checking).snapshot is None
    with pytest.raises(ValidationError, match="include a timezone"):
        calculated_account_balance(checking, as_of=observed_at.replace(tzinfo=None))
    with pytest.raises(ValidationError, match="another household"):
        record_balance_snapshot(
            household=ledger_context.household,
            actor=ledger_context.user,
            account=other_account,
            observed_balance=Decimal("1.00"),
            observed_at=observed_at,
            request_id="request-cross-household-snapshot",
        )

    invalid_balances = (
        ("1.00", "Decimal values"),
        (Decimal("NaN"), "invalid"),
        (Decimal("1.001"), "two decimal places"),
    )
    for observed_balance, message in invalid_balances:
        with pytest.raises(ValidationError, match=message):
            record_balance_snapshot(
                household=ledger_context.household,
                actor=ledger_context.user,
                account=checking,
                observed_balance=observed_balance,  # type: ignore[arg-type]
                observed_at=observed_at,
                request_id=f"request-invalid-snapshot-{message}",
            )

    with pytest.raises(ValidationError, match="include a timezone"):
        record_balance_snapshot(
            household=ledger_context.household,
            actor=ledger_context.user,
            account=checking,
            observed_balance=Decimal("1.00"),
            observed_at=observed_at.replace(tzinfo=None),
            request_id="request-naive-snapshot",
        )
