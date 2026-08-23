from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from typing import cast
from zoneinfo import ZoneInfo

import pytest
from django import forms
from django.core.exceptions import ValidationError
from django.test import Client
from django.urls import reverse

from audit.models import AuditEvent
from households.models import Category, Household, HouseholdMembership
from households.services.categories import create_category
from identity.models import User
from identity.services.mfa import (
    begin_enrollment,
    confirm_enrollment,
    confirm_recovery_codes_saved,
    totp_code,
)
from ledger.models import FinancialAccount, JournalEntry
from ledger.services import create_financial_account, record_expense, reverse_entry
from periods.models import PayPeriod
from reserves.models import CardPaymentReserveEntry
from spending.forms import (
    CardPaymentForm,
    ExpenseForm,
    FinancialAccountForm,
    IncomeForm,
    ReversalForm,
)
from spending.services import credit_card_payment_reserve

TEST_PASSWORD = "spending-ui-test-password"  # pragma: allowlist secret


@dataclass(frozen=True, slots=True)
class SpendingContext:
    household: Household
    user: User
    outsider: User
    period: PayPeriod
    checking: FinancialAccount
    category: Category


def _mfa_ready(user: User) -> None:
    enrollment = begin_enrollment(user)
    assert confirm_enrollment(user, totp_code(enrollment.secret)) is not None
    assert confirm_recovery_codes_saved(user) is True
    user.refresh_from_db()


@pytest.fixture
def spending_context(db: object) -> SpendingContext:
    household = Household.objects.create(name="Nelson Household")
    user = User.objects.create_user(email="member@example.com", password=TEST_PASSWORD)
    outsider = User.objects.create_user(email="outsider@example.com", password=TEST_PASSWORD)
    HouseholdMembership.objects.create(household=household, user=user)
    period = PayPeriod.objects.create(
        household=household,
        start_date=date(2026, 8, 20),
        next_start_date=date(2026, 8, 27),
        status=PayPeriod.Status.OPEN,
        created_by=user,
    )
    checking = create_financial_account(
        household=household,
        actor=user,
        name="Checking",
        account_type=FinancialAccount.AccountType.CHECKING,
        classification=FinancialAccount.Classification.ASSET,
        last_four="1190",
        request_id="spending-test-account",
    )
    category = create_category(
        household=household,
        actor=user,
        name="Groceries",
        color="#49D6A6",
        sort_order=10,
        request_id="spending-test-category",
    )
    return SpendingContext(household, user, outsider, period, checking, category)


def _expense_payload(context: SpendingContext, *, token: uuid.UUID | None = None) -> dict[str, str]:
    return {
        "description": "Weekly groceries",
        "amount": "83.42",
        "account": str(context.checking.pk),
        "category": str(context.category.pk),
        "effective_date": "2026-08-22",
        "effective_time": "19:35",
        "receipt_reference": "receipt-0822",
        "note": "Manual transaction test",
        "submission_token": str(token or uuid.uuid4()),
    }


@pytest.mark.django_db
def test_transaction_pages_require_login(client: Client) -> None:
    urls = (
        reverse("spending:transaction-list"),
        reverse("spending:expense-create"),
        reverse("spending:income-create"),
        reverse("spending:account-create"),
    )
    for url in urls:
        response = client.get(url)
        assert response.status_code == 302
        assert response.headers["Location"].startswith(reverse("identity:login"))


@pytest.mark.django_db
def test_spending_mutations_require_csrf_and_allowed_methods(
    spending_context: SpendingContext,
) -> None:
    _mfa_ready(spending_context.user)
    csrf_client = Client(enforce_csrf_checks=True)
    csrf_client.force_login(spending_context.user)

    rejected = csrf_client.post(
        reverse("spending:expense-create"),
        _expense_payload(spending_context),
    )
    assert rejected.status_code == 403
    assert not JournalEntry.objects.filter(description="Weekly groceries").exists()

    method_client = Client()
    method_client.force_login(spending_context.user)
    method_rejected = method_client.put(reverse("spending:income-create"), data={})
    assert method_rejected.status_code == 405


@pytest.mark.django_db
def test_manual_expense_is_household_scoped_audited_and_idempotent(
    client: Client,
    spending_context: SpendingContext,
) -> None:
    _mfa_ready(spending_context.user)
    client.force_login(spending_context.user)
    token = uuid.uuid4()
    payload = _expense_payload(spending_context, token=token)

    response = client.post(reverse("spending:expense-create"), payload)

    assert response.status_code == 302
    entry = JournalEntry.objects.get(description="Weekly groceries")
    assert response.headers["Location"] == reverse(
        "spending:transaction-detail",
        args=(entry.pk,),
    )
    assert entry.household == spending_context.household
    assert entry.entry_type == JournalEntry.EntryType.EXPENSE
    assert entry.category == spending_context.category
    assert entry.effective_at == datetime(
        2026,
        8,
        22,
        19,
        35,
        tzinfo=ZoneInfo("America/New_York"),
    )
    assert entry.idempotency_key == f"manual-{token.hex}"
    assert AuditEvent.objects.filter(
        household=spending_context.household,
        action="ledger.expense_recorded",
        entity_id=str(entry.pk),
    ).exists()

    replay = client.post(reverse("spending:expense-create"), payload)
    assert replay.status_code == 200
    assert b"already been used" in replay.content
    assert JournalEntry.objects.filter(description="Weekly groceries").count() == 1


@pytest.mark.django_db
def test_manual_income_and_account_setup_succeed(
    client: Client,
    spending_context: SpendingContext,
) -> None:
    _mfa_ready(spending_context.user)
    client.force_login(spending_context.user)

    account_response = client.post(
        reverse("spending:account-create"),
        {
            "name": "Rewards card",
            "kind": FinancialAccountForm.Kind.CREDIT_CARD,
            "last_four": "4411",
            "notes": "No full card number stored",
        },
    )
    assert account_response.status_code == 302
    card = FinancialAccount.objects.get(name="Rewards card")
    assert card.classification == FinancialAccount.Classification.LIABILITY
    assert card.account_type == FinancialAccount.AccountType.CREDIT_CARD
    assert AuditEvent.objects.filter(action="account.created", entity_id=str(card.pk)).exists()

    income_response = client.post(
        reverse("spending:income-create"),
        {
            "description": "One-off bonus",
            "amount": "125.50",
            "destination": str(spending_context.checking.pk),
            "effective_date": "2026-08-23",
            "effective_time": "08:10",
            "note": "Does not alter the recurring income schedule",
            "submission_token": str(uuid.uuid4()),
        },
    )
    assert income_response.status_code == 302
    income = JournalEntry.objects.get(description="One-off bonus")
    assert income.entry_type == JournalEntry.EntryType.INCOME
    assert AuditEvent.objects.filter(
        action="ledger.income_recorded",
        entity_id=str(income.pk),
    ).exists()

    duplicate_account = client.post(
        reverse("spending:account-create"),
        {
            "name": "rewards CARD",
            "kind": FinancialAccountForm.Kind.CREDIT_CARD,
            "last_four": "4411",
        },
    )
    assert duplicate_account.status_code == 200
    assert (
        FinancialAccount.objects.filter(
            household=spending_context.household,
            name__iexact="Rewards card",
        ).count()
        == 1
    )


@pytest.mark.django_db
def test_card_purchase_and_payment_ui_show_persistent_allocation(
    client: Client,
    spending_context: SpendingContext,
) -> None:
    card = create_financial_account(
        household=spending_context.household,
        actor=spending_context.user,
        name="Visa",
        account_type=FinancialAccount.AccountType.CREDIT_CARD,
        classification=FinancialAccount.Classification.LIABILITY,
        last_four="4242",
        request_id="spending-ui-card",
    )
    _mfa_ready(spending_context.user)
    client.force_login(spending_context.user)
    purchase_payload = _expense_payload(spending_context)
    purchase_payload["account"] = str(card.pk)
    purchase_payload["amount"] = "75.00"
    purchase_payload["description"] = "Visa groceries"

    purchase_response = client.post(reverse("spending:expense-create"), purchase_payload)
    assert purchase_response.status_code == 302
    purchase = JournalEntry.objects.get(description="Visa groceries")
    assert credit_card_payment_reserve(card) == Decimal("75.00")
    assert CardPaymentReserveEntry.objects.get(journal_entry=purchase).amount == Decimal("75.00")

    detail = client.get(reverse("spending:transaction-detail", args=(purchase.pk,)))
    assert detail.status_code == 200
    assert b"Credit-card Payment Reserve" in detail.content
    assert b"$75.00" in detail.content

    transaction_list = client.get(
        reverse("spending:transaction-list"),
        {"period": str(spending_context.period.pk)},
    )
    payment_url = reverse("spending:card-payment-create", args=(card.pk,))
    assert b"$75.00 reserved for payment" in transaction_list.content
    assert payment_url.encode() in transaction_list.content

    payment_form = client.get(payment_url)
    assert payment_form.status_code == 200
    assert b"Available payment reserve: $75.00" in payment_form.content
    payment_response = client.post(
        payment_url,
        {
            "description": "Visa payment",
            "amount": "100.00",
            "source": str(spending_context.checking.pk),
            "effective_date": "2026-08-24",
            "effective_time": "09:15",
            "note": "Includes old-debt payoff",
            "submission_token": str(uuid.uuid4()),
        },
    )
    assert payment_response.status_code == 302
    payment = JournalEntry.objects.get(description="Visa payment")
    allocation = CardPaymentReserveEntry.objects.get(journal_entry=payment)
    assert allocation.reserve_settlement == Decimal("75.00")
    assert allocation.debt_payoff == Decimal("25.00")
    assert credit_card_payment_reserve(card) == Decimal("0.00")

    payment_detail = client.get(reverse("spending:transaction-detail", args=(payment.pk,)))
    assert b"Reserved purchase settlement" in payment_detail.content
    assert b"Current-income debt payoff" in payment_detail.content
    assert b"$25.00" in payment_detail.content

    payment_form_object = CardPaymentForm(household=spending_context.household)
    source_accounts = cast(
        forms.ModelChoiceField,
        payment_form_object.fields["source"],
    ).queryset
    assert source_accounts is not None
    assert spending_context.checking in source_accounts
    assert card not in source_accounts


@pytest.mark.django_db
def test_transaction_list_defaults_to_paycheck_period_and_filters(
    client: Client,
    spending_context: SpendingContext,
) -> None:
    _mfa_ready(spending_context.user)
    client.force_login(spending_context.user)
    current = record_expense(
        household=spending_context.household,
        actor=spending_context.user,
        account=spending_context.checking,
        category=spending_context.category,
        amount=Decimal("20.00"),
        effective_at=datetime(2026, 8, 22, 12, tzinfo=ZoneInfo("America/New_York")),
        description="Current groceries",
        request_id="current-spending-entry",
    )
    record_expense(
        household=spending_context.household,
        actor=spending_context.user,
        account=spending_context.checking,
        category=spending_context.category,
        amount=Decimal("15.00"),
        effective_at=datetime(2026, 8, 10, 12, tzinfo=ZoneInfo("America/New_York")),
        description="Older groceries",
        request_id="older-spending-entry",
    )

    selected = client.get(
        reverse("spending:transaction-list"),
        {"period": str(spending_context.period.pk)},
    )
    assert selected.status_code == 200
    assert b"Current groceries" in selected.content
    assert b"Older groceries" not in selected.content
    assert b"This pay period" in selected.content

    all_history = client.get(
        reverse("spending:transaction-list"),
        {
            "scope": "all",
            "q": "Current",
            "entry_type": JournalEntry.EntryType.EXPENSE,
            "account": str(spending_context.checking.pk),
        },
    )
    assert all_history.status_code == 200
    assert b"Current groceries" in all_history.content
    assert b"Older groceries" not in all_history.content
    assert b'name="scope" value="all"' in all_history.content
    assert (
        reverse("spending:transaction-detail", args=(current.pk,)).encode() in all_history.content
    )


@pytest.mark.django_db
def test_full_refund_reversal_is_confirmed_linked_and_audited(
    client: Client,
    spending_context: SpendingContext,
) -> None:
    _mfa_ready(spending_context.user)
    client.force_login(spending_context.user)
    original = record_expense(
        household=spending_context.household,
        actor=spending_context.user,
        account=spending_context.checking,
        category=spending_context.category,
        amount=Decimal("42.00"),
        effective_at=datetime(2026, 8, 22, 12, tzinfo=ZoneInfo("America/New_York")),
        description="Returned purchase",
        request_id="original-returned-purchase",
    )
    reverse_url = reverse("spending:transaction-reverse", args=(original.pk,))
    reversal_form_page = client.get(reverse_url)
    assert reversal_form_page.status_code == 200
    assert b"permanent linked reversal" in reversal_form_page.content
    missing_confirmation = client.post(
        reverse_url,
        {
            "effective_date": "2026-08-24",
            "effective_time": "09:00",
            "reason": "Merchant refunded the full purchase",
        },
    )
    assert missing_confirmation.status_code == 200
    assert b"This field is required" in missing_confirmation.content
    assert not JournalEntry.objects.filter(reversal_of=original).exists()

    response = client.post(
        reverse_url,
        {
            "effective_date": "2026-08-24",
            "effective_time": "09:00",
            "reason": "Merchant refunded the full purchase",
            "confirm": "on",
        },
    )
    assert response.status_code == 302
    reversal = JournalEntry.objects.get(reversal_of=original)
    assert response.headers["Location"] == reverse(
        "spending:transaction-detail",
        args=(reversal.pk,),
    )
    assert reversal.note == "Merchant refunded the full purchase"
    assert AuditEvent.objects.filter(
        action="ledger.entry_reversed",
        entity_id=str(reversal.pk),
        reason="Merchant refunded the full purchase",
    ).exists()
    assert client.get(reverse_url).status_code == 404
    assert b"This entry reverses" in client.get(response.headers["Location"]).content

    with pytest.raises(ValidationError, match="cannot itself be reversed"):
        reverse_entry(
            entry=reversal,
            actor=spending_context.user,
            effective_at=datetime(2026, 8, 25, 9, tzinfo=ZoneInfo("America/New_York")),
            reason="Invalid chained reversal",
            request_id="reject-reversal-chain",
        )


@pytest.mark.django_db
def test_direct_object_access_and_form_choices_fail_closed(
    client: Client,
    spending_context: SpendingContext,
) -> None:
    other_household = Household.objects.create(name="Other Household")
    HouseholdMembership.objects.create(
        household=other_household,
        user=spending_context.outsider,
    )
    other_account = create_financial_account(
        household=other_household,
        actor=spending_context.outsider,
        name="Other checking",
        account_type=FinancialAccount.AccountType.CHECKING,
        classification=FinancialAccount.Classification.ASSET,
        request_id="other-spending-account",
    )
    other_category = create_category(
        household=other_household,
        actor=spending_context.outsider,
        name="Other category",
        color="#64748B",
        sort_order=0,
        request_id="other-spending-category",
    )
    other_entry = record_expense(
        household=other_household,
        actor=spending_context.outsider,
        account=other_account,
        category=other_category,
        amount=Decimal("9.00"),
        effective_at=datetime(2026, 8, 22, 12, tzinfo=ZoneInfo("America/New_York")),
        description="Private other-household entry",
        request_id="other-spending-entry",
    )
    _mfa_ready(spending_context.user)
    client.force_login(spending_context.user)

    detail_url = reverse("spending:transaction-detail", args=(other_entry.pk,))
    reverse_url = reverse("spending:transaction-reverse", args=(other_entry.pk,))
    payment_url = reverse("spending:card-payment-create", args=(other_account.pk,))
    assert client.get(detail_url).status_code == 404
    assert client.get(reverse_url).status_code == 404
    assert client.get(payment_url).status_code == 404
    list_response = client.get(reverse("spending:transaction-list"), {"scope": "all"})
    assert b"Private other-household entry" not in list_response.content

    expense_form = ExpenseForm(household=spending_context.household)
    income_form = IncomeForm(household=spending_context.household)
    expense_accounts = cast(forms.ModelChoiceField, expense_form.fields["account"]).queryset
    income_accounts = cast(forms.ModelChoiceField, income_form.fields["destination"]).queryset
    categories = cast(forms.ModelChoiceField, expense_form.fields["category"]).queryset
    assert expense_accounts is not None
    assert income_accounts is not None
    assert categories is not None
    assert other_account not in expense_accounts
    assert other_account not in income_accounts
    assert other_category not in categories


@pytest.mark.django_db
def test_spending_forms_render_and_invalid_period_or_filters_fail_safely(
    client: Client,
    spending_context: SpendingContext,
) -> None:
    _mfa_ready(spending_context.user)
    client.force_login(spending_context.user)
    for url in (
        reverse("spending:expense-create"),
        reverse("spending:income-create"),
        reverse("spending:account-create"),
    ):
        response = client.get(url)
        assert response.status_code == 200
        assert b"<form" in response.content

    invalid_filter = client.get(
        reverse("spending:transaction-list"),
        {
            "period": "not-a-uuid",
            "account": "not-a-uuid",
        },
    )
    assert invalid_filter.status_code == 200
    assert b"This pay period" in invalid_filter.content

    invalid_expense = ExpenseForm(data={}, household=spending_context.household)
    with pytest.raises(ValidationError, match="Correct the transaction"):
        invalid_expense.effective_at()
    with pytest.raises(ValidationError, match="Correct the transaction"):
        invalid_expense.idempotency_key()

    invalid_account = FinancialAccountForm(data={})
    with pytest.raises(ValidationError, match="Correct the account"):
        invalid_account.account_type_and_classification()

    invalid_reversal = ReversalForm(data={}, household=spending_context.household)
    with pytest.raises(ValidationError, match="Correct the reversal"):
        invalid_reversal.effective_at()


@pytest.mark.django_db
def test_transaction_history_handles_a_household_without_paycheck_periods(
    client: Client,
) -> None:
    household = Household.objects.create(name="No periods household")
    user = User.objects.create_user(email="no-periods@example.com", password=TEST_PASSWORD)
    HouseholdMembership.objects.create(household=household, user=user)
    _mfa_ready(user)
    client.force_login(user)

    response = client.get(
        reverse("spending:transaction-list"),
        {"period": str(uuid.uuid4())},
    )
    assert response.status_code == 200
    assert b"All transaction history" in response.content
    assert b"No transactions found" in response.content


def test_financial_account_form_maps_every_supported_kind() -> None:
    expectations = (
        (
            FinancialAccountForm.Kind.CHECKING,
            FinancialAccount.AccountType.CHECKING,
            FinancialAccount.Classification.ASSET,
        ),
        (
            FinancialAccountForm.Kind.SAVINGS,
            FinancialAccount.AccountType.SAVINGS,
            FinancialAccount.Classification.ASSET,
        ),
        (
            FinancialAccountForm.Kind.CASH,
            FinancialAccount.AccountType.CASH,
            FinancialAccount.Classification.ASSET,
        ),
        (
            FinancialAccountForm.Kind.CREDIT_CARD,
            FinancialAccount.AccountType.CREDIT_CARD,
            FinancialAccount.Classification.LIABILITY,
        ),
        (
            FinancialAccountForm.Kind.OTHER_ASSET,
            FinancialAccount.AccountType.OTHER,
            FinancialAccount.Classification.ASSET,
        ),
        (
            FinancialAccountForm.Kind.OTHER_LIABILITY,
            FinancialAccount.AccountType.OTHER,
            FinancialAccount.Classification.LIABILITY,
        ),
    )
    for kind, account_type, classification in expectations:
        form = FinancialAccountForm(data={"name": "Test", "kind": kind})
        assert form.is_valid(), form.errors
        assert form.account_type_and_classification() == (account_type, classification)
