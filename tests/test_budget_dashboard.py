from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.urls import reverse

from audit.models import AuditEvent
from budgets.forms import FixedExpenseScheduleForm, OccurrenceMoveForm, ReconciliationForm
from budgets.models import OccurrenceReconciliation, VariableBudget
from budgets.services import (
    build_period_summary,
    delete_variable_budget,
    reconcile_occurrence,
    set_variable_budget,
)
from budgets.services.reconciliation import _positive_money
from budgets.services.variable_budgets import _money as _budget_money
from budgets.templatetags.budget_tags import money as display_money
from budgets.templatetags.budget_tags import occurrence_status
from households.models import Category, Household, HouseholdMembership
from households.services.categories import create_category
from identity.models import User
from identity.services.mfa import (
    begin_enrollment,
    confirm_enrollment,
    confirm_recovery_codes_saved,
    totp_code,
)
from ledger.models import FinancialAccount
from ledger.services import (
    create_financial_account,
    record_expense,
    record_income,
    reverse_entry,
)
from periods.models import PayPeriod
from periods.services import close_period
from reserves.services import _signed_money, allocate_reserve, reserve_balance
from schedules.models import Occurrence, RecurringSource
from schedules.recurrence import BusinessDayAdjustment, Frequency, RecurrenceRule
from schedules.services import (
    RevisionSpec,
    complete_occurrence,
    create_recurring_source,
    preview_revision,
)
from spending.services import record_card_payment, record_spending_expense

TEST_PASSWORD = "budget-dashboard-test-password"  # pragma: allowlist secret


@dataclass(frozen=True)
class BudgetContext:
    household: Household
    user: User
    outsider: User
    period: PayPeriod
    category: Category
    checking: FinancialAccount


@pytest.fixture
def budget_context(db: object) -> BudgetContext:
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
    category = create_category(
        household=household,
        actor=user,
        name="Groceries",
        color="#49D6A6",
        sort_order=10,
        request_id="budget-category-create",
    )
    checking = create_financial_account(
        household=household,
        actor=user,
        name="Checking",
        account_type=FinancialAccount.AccountType.CHECKING,
        classification=FinancialAccount.Classification.ASSET,
        request_id="budget-account-create",
    )
    return BudgetContext(household, user, outsider, period, category, checking)


def _source_occurrence(
    context: BudgetContext,
    *,
    kind: str,
    name: str,
    amount: str,
    expected_date: date = date(2026, 8, 21),
    category: Category | None = None,
) -> Occurrence:
    specification = RevisionSpec(
        effective_from=expected_date,
        expected_amount=Decimal(amount),
        rule=RecurrenceRule(Frequency.ONCE, expected_date),
        adjustment_policy=BusinessDayAdjustment.NONE,
    )
    preview = preview_revision(specification, preview_from=expected_date)
    source, revision = create_recurring_source(
        household=context.household,
        actor=context.user,
        kind=kind,
        name=name,
        revision_spec=specification,
        expected_preview_fingerprint=preview.fingerprint,
        expense_category=category,
        request_id=f"budget-source-{name.lower().replace(' ', '-')}",
    )
    return Occurrence.objects.create(
        source=source,
        source_revision=revision,
        nominal_date=expected_date,
        generated_expected_date=expected_date,
        expected_date=expected_date,
        generated_amount=Decimal(amount),
        planned_amount=Decimal(amount),
        pay_period=context.period,
    )


def _complete(context: BudgetContext, occurrence: Occurrence, amount: str) -> None:
    complete_occurrence(
        occurrence=occurrence,
        actor=context.user,
        actual_amount=Decimal(amount),
        actual_date=occurrence.expected_date,
        request_id=f"budget-complete-{occurrence.source.name.lower().replace(' ', '-')}",
    )


def _mfa_ready(user: User) -> None:
    enrollment = begin_enrollment(user)
    assert confirm_enrollment(user, totp_code(enrollment.secret)) is not None
    assert confirm_recovery_codes_saved(user) is True
    user.refresh_from_db()


@pytest.mark.django_db
def test_dashboard_summary_matches_golden_case_a(budget_context: BudgetContext) -> None:
    income = _source_occurrence(
        budget_context,
        kind=RecurringSource.Kind.INCOME,
        name="Paycheck",
        amount="2840.00",
    )
    fixed = _source_occurrence(
        budget_context,
        kind=RecurringSource.Kind.FIXED_EXPENSE,
        name="Mortgage installment",
        amount="1000.00",
        category=budget_context.category,
    )
    debt = _source_occurrence(
        budget_context,
        kind=RecurringSource.Kind.DEBT_PAYMENT,
        name="Car payment",
        amount="926.50",
    )
    goal = _source_occurrence(
        budget_context,
        kind=RecurringSource.Kind.GOAL_CONTRIBUTION,
        name="Emergency fund",
        amount="350.00",
    )
    for occurrence, amount in (
        (income, "2840.00"),
        (fixed, "1000.00"),
        (debt, "926.50"),
        (goal, "350.00"),
    ):
        _complete(budget_context, occurrence, amount)
    set_variable_budget(
        pay_period=budget_context.period,
        category=budget_context.category,
        planned_amount=Decimal("420.00"),
        actor=budget_context.user,
        request_id="budget-variable-create",
    )
    record_expense(
        household=budget_context.household,
        actor=budget_context.user,
        account=budget_context.checking,
        category=budget_context.category,
        amount=Decimal("133.60"),
        effective_at=datetime(2026, 8, 22, 12, tzinfo=ZoneInfo("America/New_York")),
        description="Groceries",
        request_id="budget-grocery-spend",
    )

    summary = build_period_summary(
        household=budget_context.household,
        period=budget_context.period,
        today=date(2026, 8, 22),
    )

    assert summary.allocatable_amount == Decimal("563.50")
    assert summary.unallocated_excess == Decimal("143.50")
    assert summary.spending_remaining == Decimal("286.40")
    assert summary.projected_closing_surplus == Decimal("429.90")
    assert summary.actual_variable_spending == Decimal("133.60")
    assert summary.status == "on_track"


@pytest.mark.django_db
def test_one_time_bonus_increases_actual_income_without_moving_boundaries(
    budget_context: BudgetContext,
) -> None:
    paycheck = _source_occurrence(
        budget_context,
        kind=RecurringSource.Kind.INCOME,
        name="Base paycheck",
        amount="2650.00",
    )
    _complete(budget_context, paycheck, "2650.00")
    original_range = (budget_context.period.start_date, budget_context.period.next_start_date)
    record_income(
        household=budget_context.household,
        actor=budget_context.user,
        destination=budget_context.checking,
        amount=Decimal("190.00"),
        effective_at=datetime(2026, 8, 23, 8, tzinfo=ZoneInfo("America/New_York")),
        description="One-time bonus",
        request_id="budget-one-time-bonus",
    )

    summary = build_period_summary(
        household=budget_context.household,
        period=budget_context.period,
        today=date(2026, 8, 23),
    )
    budget_context.period.refresh_from_db()

    assert summary.planned_income == Decimal("2650.00")
    assert summary.actual_income == Decimal("2840.00")
    assert summary.unallocated_excess == Decimal("2840.00")
    assert (
        budget_context.period.start_date,
        budget_context.period.next_start_date,
    ) == original_range


@pytest.mark.django_db
def test_completed_paycheck_shortfall_marks_dashboard_for_attention(
    budget_context: BudgetContext,
) -> None:
    paycheck = _source_occurrence(
        budget_context,
        kind=RecurringSource.Kind.INCOME,
        name="Short paycheck",
        amount="1500.00",
    )
    _complete(budget_context, paycheck, "1400.00")

    summary = build_period_summary(
        household=budget_context.household,
        period=budget_context.period,
        today=date(2026, 8, 23),
    )

    assert summary.status == "attention"
    assert summary.status_label == "Attention needed"


@pytest.mark.django_db
def test_variable_budgets_are_household_scoped_audited_and_closed_period_safe(
    budget_context: BudgetContext,
) -> None:
    budget = set_variable_budget(
        pay_period=budget_context.period,
        category=budget_context.category,
        planned_amount=Decimal("420.00"),
        actor=budget_context.user,
        request_id="budget-variable-set-one",
    )
    updated = set_variable_budget(
        pay_period=budget_context.period,
        category=budget_context.category,
        planned_amount=Decimal("450.00"),
        actor=budget_context.user,
        request_id="budget-variable-set-two",
    )

    assert updated.pk == budget.pk
    assert VariableBudget.objects.count() == 1
    assert AuditEvent.objects.filter(action="budget.variable_created").count() == 1
    assert AuditEvent.objects.filter(action="budget.variable_updated").count() == 1
    with pytest.raises(PermissionDenied):
        set_variable_budget(
            pay_period=budget_context.period,
            category=budget_context.category,
            planned_amount=Decimal("10.00"),
            actor=budget_context.outsider,
            request_id="budget-outsider-update",
        )
    budget_context.period.status = PayPeriod.Status.CLOSED
    budget_context.period.save(update_fields=("status",))
    with pytest.raises(ValidationError, match="Reopen"):
        set_variable_budget(
            pay_period=budget_context.period,
            category=budget_context.category,
            planned_amount=Decimal("10.00"),
            actor=budget_context.user,
            request_id="budget-closed-update",
        )


@pytest.mark.django_db
def test_reconciliation_links_actual_entry_and_is_append_only(
    budget_context: BudgetContext,
) -> None:
    bill = _source_occurrence(
        budget_context,
        kind=RecurringSource.Kind.FIXED_EXPENSE,
        name="Power bill",
        amount="75.00",
        category=budget_context.category,
    )
    entry = record_expense(
        household=budget_context.household,
        actor=budget_context.user,
        account=budget_context.checking,
        category=budget_context.category,
        amount=Decimal("75.00"),
        effective_at=datetime(2026, 8, 22, 12, tzinfo=ZoneInfo("America/New_York")),
        description="Power company",
        request_id="budget-power-entry",
    )
    link = reconcile_occurrence(
        occurrence=bill,
        journal_entry=entry,
        amount=Decimal("75.00"),
        actor=budget_context.user,
        request_id="budget-power-reconcile",
    )
    bill.refresh_from_db()

    assert bill.actual_amount == Decimal("75.00")
    assert bill.status == Occurrence.Status.COMPLETED
    assert link.household == budget_context.household
    assert AuditEvent.objects.filter(action="budget.occurrence_reconciled").exists()
    with pytest.raises(ValidationError, match="cannot be updated"):
        link.save()
    with pytest.raises(ValidationError, match="cannot be updated"):
        OccurrenceReconciliation.objects.filter(pk=link.pk).update(amount=Decimal("1.00"))
    with pytest.raises(ValidationError, match="already linked"):
        reconcile_occurrence(
            occurrence=bill,
            journal_entry=entry,
            amount=Decimal("1.00"),
            actor=budget_context.user,
            request_id="budget-power-reconcile-twice",
        )


@pytest.mark.django_db
def test_card_payment_reconciliation_uses_only_current_income_debt_payoff(
    budget_context: BudgetContext,
) -> None:
    card = create_financial_account(
        household=budget_context.household,
        actor=budget_context.user,
        name="Visa",
        account_type=FinancialAccount.AccountType.CREDIT_CARD,
        classification=FinancialAccount.Classification.LIABILITY,
        request_id="budget-card-reconciliation-account",
    )
    first_purchase = record_spending_expense(
        household=budget_context.household,
        actor=budget_context.user,
        account=card,
        category=budget_context.category,
        amount=Decimal("40.00"),
        effective_at=datetime(2026, 8, 21, 8, tzinfo=ZoneInfo("America/New_York")),
        description="Covered purchase",
        request_id="budget-card-covered-purchase",
    )
    covered_payment = record_card_payment(
        household=budget_context.household,
        actor=budget_context.user,
        source=budget_context.checking,
        card=card,
        amount=Decimal("40.00"),
        effective_at=datetime(2026, 8, 21, 9, tzinfo=ZoneInfo("America/New_York")),
        description="Covered card payment",
        request_id="budget-card-covered-payment",
    )
    record_spending_expense(
        household=budget_context.household,
        actor=budget_context.user,
        account=card,
        category=budget_context.category,
        amount=Decimal("50.00"),
        effective_at=datetime(2026, 8, 22, 8, tzinfo=ZoneInfo("America/New_York")),
        description="Mixed purchase",
        request_id="budget-card-mixed-purchase",
    )
    mixed_payment = record_card_payment(
        household=budget_context.household,
        actor=budget_context.user,
        source=budget_context.checking,
        card=card,
        amount=Decimal("75.00"),
        effective_at=datetime(2026, 8, 22, 9, tzinfo=ZoneInfo("America/New_York")),
        description="Mixed card payment",
        request_id="budget-card-mixed-payment",
    )
    scheduled_debt = _source_occurrence(
        budget_context,
        kind=RecurringSource.Kind.DEBT_PAYMENT,
        name="Visa old balance",
        amount="25.00",
    )

    form = ReconciliationForm(household=budget_context.household, occurrence=scheduled_debt)
    entry_ids = set(form.fields["journal_entry"].queryset.values_list("pk", flat=True))  # type: ignore[attr-defined]

    assert first_purchase.pk not in entry_ids
    assert covered_payment.journal_entry.pk not in entry_ids
    assert mixed_payment.journal_entry.pk in entry_ids
    link = reconcile_occurrence(
        occurrence=scheduled_debt,
        journal_entry=mixed_payment.journal_entry,
        amount=Decimal("25.00"),
        actor=budget_context.user,
        request_id="budget-card-mixed-reconcile",
    )
    assert link.amount == Decimal("25.00")

    another_debt = _source_occurrence(
        budget_context,
        kind=RecurringSource.Kind.DEBT_PAYMENT,
        name="Visa excess link",
        amount="1.00",
    )
    with pytest.raises(ValidationError, match="cannot exceed"):
        reconcile_occurrence(
            occurrence=another_debt,
            journal_entry=mixed_payment.journal_entry,
            amount=Decimal("0.01"),
            actor=budget_context.user,
            request_id="budget-card-over-reconcile",
        )

    summary = build_period_summary(
        household=budget_context.household,
        period=budget_context.period,
        today=date(2026, 8, 22),
    )
    assert summary.actual_debt_payments == Decimal("25.00")


@pytest.mark.django_db
def test_golden_case_c_explicit_reserve_allocations_are_protected_history(
    budget_context: BudgetContext,
) -> None:
    prior_period = PayPeriod.objects.create(
        household=budget_context.household,
        start_date=date(2026, 8, 13),
        next_start_date=date(2026, 8, 20),
        status=PayPeriod.Status.OPEN,
        created_by=budget_context.user,
    )
    close_period(
        pay_period=prior_period,
        actor=budget_context.user,
        closing_surplus=Decimal("929.90"),
        request_id="budget-close-for-reserve",
    )
    first = allocate_reserve(
        household=budget_context.household,
        actor=budget_context.user,
        posting_period=budget_context.period,
        amount=Decimal("300.00"),
        allocation_label="Emergency Fund",
        request_id="budget-reserve-emergency",
    )
    second = allocate_reserve(
        household=budget_context.household,
        actor=budget_context.user,
        posting_period=budget_context.period,
        amount=Decimal("100.00"),
        allocation_label="Extra Visa principal",
        request_id="budget-reserve-visa",
    )

    assert first.amount == Decimal("-300.00")
    assert second.amount == Decimal("-100.00")
    assert reserve_balance(budget_context.household) == Decimal("529.90")
    assert AuditEvent.objects.filter(action="reserve.explicit_allocation_recorded").count() == 2
    with pytest.raises(ValidationError, match="cannot be updated"):
        second.save()
    with pytest.raises(ValidationError, match="cannot exceed"):
        allocate_reserve(
            household=budget_context.household,
            actor=budget_context.user,
            posting_period=budget_context.period,
            amount=Decimal("600.00"),
            allocation_label="Too much",
            request_id="budget-reserve-excess",
        )


@pytest.mark.django_db
def test_budget_dashboard_and_fixed_expense_preview_are_responsive_authenticated_workflows(
    client,
    budget_context: BudgetContext,
) -> None:  # type: ignore[no-untyped-def]
    _mfa_ready(budget_context.user)
    client.force_login(budget_context.user)

    home_response = client.get(reverse("core:home"))
    budget_response = client.get(reverse("budgets:detail", args=(budget_context.period.pk,)))

    assert home_response.status_code == 200
    assert b"Paycheck period" in home_response.content
    assert b"Not a verified bank balance" in home_response.content
    assert b'class="mobile-nav"' in home_response.content
    assert b"style=" not in home_response.content
    assert budget_response.status_code == 200
    assert b"Changes to generated rows affect this pay period only" in budget_response.content
    assert budget_response.headers["Cache-Control"] == "no-store, private"

    variable_budget = set_variable_budget(
        pay_period=budget_context.period,
        category=budget_context.category,
        planned_amount=Decimal("125.00"),
        actor=budget_context.user,
        request_id="budget-ui-variable-create",
    )
    confirmation = client.get(reverse("budgets:variable-delete", args=(variable_budget.pk,)))
    assert confirmation.status_code == 200
    assert b"Confirmation required" in confirmation.content
    not_confirmed = client.post(
        reverse("budgets:variable-delete", args=(variable_budget.pk,)),
        {"reason": "Changing the plan"},
    )
    assert not_confirmed.status_code == 200
    assert VariableBudget.objects.filter(pk=variable_budget.pk).exists()
    removed = client.post(
        reverse("budgets:variable-delete", args=(variable_budget.pk,)),
        {"reason": "Changing the plan", "confirm": "on"},
    )
    assert removed.status_code == 302
    assert not VariableBudget.objects.filter(pk=variable_budget.pk).exists()
    assert AuditEvent.objects.filter(action="budget.variable_deleted").exists()

    payload = {
        "name": "Internet",
        "category": str(budget_context.category.pk),
        "expected_amount": "85.00",
        "frequency": Frequency.ONCE.value,
        "interval": "1",
        "start_date": "2026-08-22",
        "end_date": "",
        "day_of_month": "",
        "weekday": "",
        "ordinal": "",
        "month_of_year": "",
        "adjustment_policy": BusinessDayAdjustment.PREVIOUS.value,
        "is_required": "on",
        "notes": "Home internet",
        "action": "preview",
    }
    preview_response = client.post(
        reverse("budgets:fixed-create", args=(budget_context.period.pk,)),
        payload,
    )
    assert preview_response.status_code == 200
    preview = preview_response.context["preview"]
    assert preview is not None
    assert b"Next due dates" in preview_response.content
    payload.update(
        {
            "action": "confirm",
            "preview_fingerprint": preview.fingerprint,
        }
    )
    confirm_response = client.post(
        reverse("budgets:fixed-create", args=(budget_context.period.pk,)),
        payload,
    )

    assert confirm_response.status_code == 302
    source = RecurringSource.objects.get(name="Internet")
    assert source.expense_detail.category == budget_context.category
    assert source.occurrences.get().pay_period == budget_context.period


@pytest.mark.django_db
def test_budget_urls_do_not_expose_another_household_period(
    client,
    budget_context: BudgetContext,
) -> None:  # type: ignore[no-untyped-def]
    _mfa_ready(budget_context.user)
    client.force_login(budget_context.user)
    other_household = Household.objects.create(name="Other Household")
    other_user = User.objects.create_user(email="other@example.com", password=TEST_PASSWORD)
    HouseholdMembership.objects.create(household=other_household, user=other_user)
    hidden_period = PayPeriod.objects.create(
        household=other_household,
        start_date=date(2026, 8, 20),
        next_start_date=date(2026, 8, 27),
        created_by=other_user,
    )

    response = client.get(reverse("budgets:detail", args=(hidden_period.pk,)))

    assert response.status_code == 404
    assert b"Other Household" not in response.content

    invalid_period = client.get(reverse("core:home") + "?period=not-a-uuid")
    invalid_category = client.get(
        reverse("budgets:detail", args=(budget_context.period.pk,)) + "?category=not-a-uuid"
    )
    assert invalid_period.status_code == 200
    assert invalid_category.status_code == 200


def test_financial_amount_validators_reject_nonfinite_and_imprecise_values() -> None:
    with pytest.raises(ValidationError, match="finite Decimal"):
        _positive_money(Decimal("NaN"))
    with pytest.raises(ValidationError, match="positive"):
        _positive_money(Decimal("1.001"))

    with pytest.raises(ValidationError, match="finite Decimal"):
        _budget_money(Decimal("Infinity"))
    with pytest.raises(ValidationError, match="nonnegative"):
        _budget_money(Decimal("-0.01"))

    with pytest.raises(ValidationError, match="finite Decimal"):
        _signed_money(Decimal("-Infinity"))
    with pytest.raises(ValidationError, match="two decimal"):
        _signed_money(Decimal("1.001"))


@pytest.mark.django_db
def test_reconciliation_rejects_wrong_household_period_state_and_entry_type(
    budget_context: BudgetContext,
) -> None:
    bill = _source_occurrence(
        budget_context,
        kind=RecurringSource.Kind.FIXED_EXPENSE,
        name="Validation bill",
        amount="75.00",
        category=budget_context.category,
    )
    expense = record_expense(
        household=budget_context.household,
        actor=budget_context.user,
        account=budget_context.checking,
        category=budget_context.category,
        amount=Decimal("75.00"),
        effective_at=datetime(2026, 8, 22, 12, tzinfo=ZoneInfo("America/New_York")),
        description="Validation expense",
        request_id="reconciliation-validation-expense",
    )
    income = record_income(
        household=budget_context.household,
        actor=budget_context.user,
        destination=budget_context.checking,
        amount=Decimal("75.00"),
        effective_at=datetime(2026, 8, 22, 13, tzinfo=ZoneInfo("America/New_York")),
        description="Validation income",
        request_id="reconciliation-validation-income",
    )

    other_household = Household.objects.create(name="Other reconciliation household")
    other_user = User.objects.create_user(
        email="other-reconciliation@example.com", password=TEST_PASSWORD
    )
    HouseholdMembership.objects.create(household=other_household, user=other_user)
    other_category = create_category(
        household=other_household,
        actor=other_user,
        name="Other expenses",
        color="#F59E0B",
        sort_order=0,
        request_id="other-reconciliation-category",
    )
    other_account = create_financial_account(
        household=other_household,
        actor=other_user,
        name="Other checking",
        account_type=FinancialAccount.AccountType.CHECKING,
        classification=FinancialAccount.Classification.ASSET,
        request_id="other-reconciliation-account",
    )
    other_entry = record_expense(
        household=other_household,
        actor=other_user,
        account=other_account,
        category=other_category,
        amount=Decimal("75.00"),
        effective_at=datetime(2026, 8, 22, 12, tzinfo=ZoneInfo("America/New_York")),
        description="Other expense",
        request_id="other-reconciliation-expense",
    )

    with pytest.raises(ValidationError, match="another household"):
        reconcile_occurrence(
            occurrence=bill,
            journal_entry=other_entry,
            amount=Decimal("75.00"),
            actor=budget_context.user,
            request_id="reject-other-household-entry",
        )

    Occurrence.objects.filter(pk=bill.pk).update(
        pay_period=None,
        status=Occurrence.Status.CANCELLED,
    )
    with pytest.raises(ValidationError, match="not assigned"):
        reconcile_occurrence(
            occurrence=bill,
            journal_entry=expense,
            amount=Decimal("75.00"),
            actor=budget_context.user,
            request_id="reject-unassigned-occurrence",
        )
    Occurrence.objects.filter(pk=bill.pk).update(
        pay_period=budget_context.period,
        status=Occurrence.Status.SCHEDULED,
    )

    budget_context.period.status = PayPeriod.Status.CLOSED
    budget_context.period.save(update_fields=("status",))
    with pytest.raises(ValidationError, match="Reopen"):
        reconcile_occurrence(
            occurrence=bill,
            journal_entry=expense,
            amount=Decimal("75.00"),
            actor=budget_context.user,
            request_id="reject-closed-period-reconciliation",
        )
    budget_context.period.status = PayPeriod.Status.OPEN
    budget_context.period.save(update_fields=("status",))

    Occurrence.objects.filter(pk=bill.pk).update(status=Occurrence.Status.CANCELLED)
    with pytest.raises(ValidationError, match="state cannot"):
        reconcile_occurrence(
            occurrence=bill,
            journal_entry=expense,
            amount=Decimal("75.00"),
            actor=budget_context.user,
            request_id="reject-cancelled-occurrence",
        )
    Occurrence.objects.filter(pk=bill.pk).update(status=Occurrence.Status.SCHEDULED)

    with pytest.raises(ValidationError, match="type does not match"):
        reconcile_occurrence(
            occurrence=bill,
            journal_entry=income,
            amount=Decimal("75.00"),
            actor=budget_context.user,
            request_id="reject-entry-type",
        )


@pytest.mark.django_db
def test_reconciliation_rejects_reversals_and_overapplication(
    budget_context: BudgetContext,
) -> None:
    reversed_bill = _source_occurrence(
        budget_context,
        kind=RecurringSource.Kind.FIXED_EXPENSE,
        name="Reversed bill",
        amount="75.00",
        category=budget_context.category,
    )
    original = record_expense(
        household=budget_context.household,
        actor=budget_context.user,
        account=budget_context.checking,
        category=budget_context.category,
        amount=Decimal("75.00"),
        effective_at=datetime(2026, 8, 22, 12, tzinfo=ZoneInfo("America/New_York")),
        description="Reversed expense",
        request_id="reconciliation-original-entry",
    )
    reversal = reverse_entry(
        entry=original,
        actor=budget_context.user,
        effective_at=datetime(2026, 8, 22, 13, tzinfo=ZoneInfo("America/New_York")),
        request_id="reconciliation-reversal-entry",
        reason="Entry was incorrect",
    )

    with pytest.raises(ValidationError, match="Reversal entries"):
        reconcile_occurrence(
            occurrence=reversed_bill,
            journal_entry=reversal,
            amount=Decimal("75.00"),
            actor=budget_context.user,
            request_id="reject-reversal-entry",
        )
    with pytest.raises(ValidationError, match="reversed journal entry"):
        reconcile_occurrence(
            occurrence=reversed_bill,
            journal_entry=original,
            amount=Decimal("75.00"),
            actor=budget_context.user,
            request_id="reject-reversed-original",
        )

    shared_entry = record_expense(
        household=budget_context.household,
        actor=budget_context.user,
        account=budget_context.checking,
        category=budget_context.category,
        amount=Decimal("75.00"),
        effective_at=datetime(2026, 8, 23, 12, tzinfo=ZoneInfo("America/New_York")),
        description="Shared expense",
        request_id="reconciliation-shared-entry",
    )
    first_bill = _source_occurrence(
        budget_context,
        kind=RecurringSource.Kind.FIXED_EXPENSE,
        name="Shared bill one",
        amount="50.00",
        category=budget_context.category,
    )
    second_bill = _source_occurrence(
        budget_context,
        kind=RecurringSource.Kind.FIXED_EXPENSE,
        name="Shared bill two",
        amount="30.00",
        category=budget_context.category,
    )
    reconcile_occurrence(
        occurrence=first_bill,
        journal_entry=shared_entry,
        amount=Decimal("50.00"),
        actor=budget_context.user,
        request_id="partially-apply-shared-entry",
    )
    with pytest.raises(ValidationError, match="cannot exceed"):
        reconcile_occurrence(
            occurrence=second_bill,
            journal_entry=shared_entry,
            amount=Decimal("30.00"),
            actor=budget_context.user,
            request_id="reject-overapplied-entry",
        )


@pytest.mark.django_db
def test_variable_budget_rejects_cross_household_archived_and_invalid_deletes(
    budget_context: BudgetContext,
) -> None:
    other_household = Household.objects.create(name="Other variable household")
    other_user = User.objects.create_user(
        email="other-variable@example.com", password=TEST_PASSWORD
    )
    HouseholdMembership.objects.create(household=other_household, user=other_user)
    other_category = create_category(
        household=other_household,
        actor=other_user,
        name="Other category",
        color="#EF4444",
        sort_order=0,
        request_id="other-variable-category",
    )
    with pytest.raises(ValidationError, match="another household"):
        set_variable_budget(
            pay_period=budget_context.period,
            category=other_category,
            planned_amount=Decimal("25.00"),
            actor=budget_context.user,
            request_id="reject-other-category",
        )

    budget_context.category.is_archived = True
    budget_context.category.save(update_fields=("is_archived",))
    with pytest.raises(ValidationError, match="Archived"):
        set_variable_budget(
            pay_period=budget_context.period,
            category=budget_context.category,
            planned_amount=Decimal("25.00"),
            actor=budget_context.user,
            request_id="reject-archived-category",
        )
    budget_context.category.is_archived = False
    budget_context.category.save(update_fields=("is_archived",))

    budget = set_variable_budget(
        pay_period=budget_context.period,
        category=budget_context.category,
        planned_amount=Decimal("25.00"),
        actor=budget_context.user,
        request_id="deletion-validation-budget",
    )
    with pytest.raises(ValidationError, match="requires a reason"):
        delete_variable_budget(
            variable_budget=budget,
            actor=budget_context.user,
            request_id="reject-blank-delete-reason",
            reason="   ",
        )

    budget_context.period.status = PayPeriod.Status.CLOSED
    budget_context.period.save(update_fields=("status",))
    with pytest.raises(ValidationError, match="Reopen"):
        delete_variable_budget(
            variable_budget=budget,
            actor=budget_context.user,
            request_id="reject-closed-period-delete",
            reason="No longer needed",
        )


@pytest.mark.django_db
def test_summary_reports_deficit_and_rejects_cross_household_period(
    budget_context: BudgetContext,
) -> None:
    _source_occurrence(
        budget_context,
        kind=RecurringSource.Kind.INCOME,
        name="Deficit paycheck",
        amount="100.00",
    )
    _source_occurrence(
        budget_context,
        kind=RecurringSource.Kind.FIXED_EXPENSE,
        name="Deficit bill",
        amount="200.00",
        category=budget_context.category,
    )

    summary = build_period_summary(
        household=budget_context.household,
        period=budget_context.period,
        today=date(2026, 8, 22),
    )
    assert summary.status == "deficit"
    assert summary.status_label == "Deficit"

    other_household = Household.objects.create(name="Wrong summary household")
    with pytest.raises(ValueError, match="another household"):
        build_period_summary(
            household=other_household,
            period=budget_context.period,
            today=date(2026, 8, 22),
        )


@pytest.mark.django_db
def test_reserve_allocations_reject_invalid_periods_amounts_and_labels(
    budget_context: BudgetContext,
) -> None:
    other_household = Household.objects.create(name="Other reserve household")
    other_user = User.objects.create_user(email="other-reserve@example.com", password=TEST_PASSWORD)
    HouseholdMembership.objects.create(household=other_household, user=other_user)
    other_period = PayPeriod.objects.create(
        household=other_household,
        start_date=date(2026, 8, 20),
        next_start_date=date(2026, 8, 27),
        status=PayPeriod.Status.OPEN,
        created_by=other_user,
    )
    with pytest.raises(ValidationError, match="another household"):
        allocate_reserve(
            household=budget_context.household,
            actor=budget_context.user,
            posting_period=other_period,
            amount=Decimal("1.00"),
            allocation_label="Other period",
            request_id="reject-other-reserve-period",
        )

    budget_context.period.status = PayPeriod.Status.CLOSED
    budget_context.period.save(update_fields=("status",))
    with pytest.raises(ValidationError, match="closed paycheck period"):
        allocate_reserve(
            household=budget_context.household,
            actor=budget_context.user,
            posting_period=budget_context.period,
            amount=Decimal("1.00"),
            allocation_label="Closed period",
            request_id="reject-closed-reserve-period",
        )
    budget_context.period.status = PayPeriod.Status.OPEN
    budget_context.period.save(update_fields=("status",))

    with pytest.raises(ValidationError, match="positive amounts"):
        allocate_reserve(
            household=budget_context.household,
            actor=budget_context.user,
            posting_period=budget_context.period,
            amount=Decimal("0.00"),
            allocation_label="Zero",
            request_id="reject-zero-reserve-allocation",
        )
    with pytest.raises(ValidationError, match="destination label"):
        allocate_reserve(
            household=budget_context.household,
            actor=budget_context.user,
            posting_period=budget_context.period,
            amount=Decimal("1.00"),
            allocation_label="   ",
            request_id="reject-blank-reserve-label",
        )
    with pytest.raises(ValidationError, match="at most 120"):
        allocate_reserve(
            household=budget_context.household,
            actor=budget_context.user,
            posting_period=budget_context.period,
            amount=Decimal("1.00"),
            allocation_label="x" * 121,
            request_id="reject-long-reserve-label",
        )


def test_budget_template_filters_cover_every_user_facing_status() -> None:
    today = date(2026, 8, 23)

    def occurrence(*, status: str, kind: str, expected_date: date) -> SimpleNamespace:
        return SimpleNamespace(
            status=status,
            source=SimpleNamespace(kind=kind),
            expected_date=expected_date,
        )

    cases = (
        (Occurrence.Status.COMPLETED, RecurringSource.Kind.INCOME, today, "Received"),
        (Occurrence.Status.COMPLETED, RecurringSource.Kind.FIXED_EXPENSE, today, "Paid"),
        (Occurrence.Status.CORRECTED, RecurringSource.Kind.INCOME, today, "Corrected"),
        (Occurrence.Status.CANCELLED, RecurringSource.Kind.INCOME, today, "Cancelled"),
        (Occurrence.Status.MOVED, RecurringSource.Kind.INCOME, today, "Moved"),
        (Occurrence.Status.OVERRIDDEN, RecurringSource.Kind.INCOME, today, "Overridden"),
        (
            Occurrence.Status.SCHEDULED,
            RecurringSource.Kind.FIXED_EXPENSE,
            date(2026, 8, 22),
            "Overdue",
        ),
        (
            Occurrence.Status.SCHEDULED,
            RecurringSource.Kind.INCOME,
            date(2026, 8, 22),
            "Scheduled",
        ),
        (
            Occurrence.Status.SCHEDULED,
            RecurringSource.Kind.FIXED_EXPENSE,
            date(2026, 8, 24),
            "Upcoming",
        ),
    )
    for status, kind, expected_date, expected in cases:
        item = occurrence(status=status, kind=kind, expected_date=expected_date)
        assert occurrence_status(item, today) == expected  # type: ignore[arg-type]

    assert display_money("12.3") == "$12.30"
    assert display_money("-12.3") == "-$12.30"
    assert display_money(object()) == "$0.00"


@pytest.mark.django_db
def test_budget_forms_cover_assigned_unassigned_and_invalid_recurrence_paths(
    budget_context: BudgetContext,
) -> None:
    bill = _source_occurrence(
        budget_context,
        kind=RecurringSource.Kind.FIXED_EXPENSE,
        name="Form bill",
        amount="25.00",
        category=budget_context.category,
    )
    assigned_form = OccurrenceMoveForm(
        household=budget_context.household,
        occurrence=bill,
    )
    assert budget_context.period not in assigned_form.fields["target_period"].queryset

    bill.pay_period = None
    unassigned_form = OccurrenceMoveForm(
        household=budget_context.household,
        occurrence=bill,
    )
    assert unassigned_form.fields["target_period"].queryset is not None

    blank_form = FixedExpenseScheduleForm(data={}, household=budget_context.household)
    with pytest.raises(ValidationError, match="Correct the schedule"):
        blank_form.revision_spec()

    invalid_weekly = FixedExpenseScheduleForm(
        data={
            "name": "Invalid weekly expense",
            "category": str(budget_context.category.pk),
            "expected_amount": "10.00",
            "frequency": Frequency.WEEKLY.value,
            "interval": "1",
            "start_date": "2026-08-20",
            "adjustment_policy": BusinessDayAdjustment.NONE.value,
        },
        household=budget_context.household,
    )
    assert invalid_weekly.is_valid() is False
    assert invalid_weekly.non_field_errors()


@pytest.mark.django_db
def test_budget_web_forms_render_and_primary_create_edit_paths_succeed(
    client,
    budget_context: BudgetContext,
) -> None:  # type: ignore[no-untyped-def]
    _mfa_ready(budget_context.user)
    client.force_login(budget_context.user)
    bill = _source_occurrence(
        budget_context,
        kind=RecurringSource.Kind.FIXED_EXPENSE,
        name="Web form bill",
        amount="25.00",
        category=budget_context.category,
    )

    filtered_detail = client.get(
        reverse("budgets:detail", args=(budget_context.period.pk,))
        + "?q=Web&kind=fixed_expense&status=scheduled"
        + f"&category={budget_context.category.pk}"
    )
    assert filtered_detail.status_code == 200

    form_urls = (
        reverse("budgets:variable-create", args=(budget_context.period.pk,)),
        reverse("budgets:category-create", args=(budget_context.period.pk,)),
        reverse("budgets:occurrence-edit", args=(bill.pk,)),
        reverse("budgets:occurrence-move", args=(bill.pk,)),
        reverse("budgets:occurrence-cancel", args=(bill.pk,)),
        reverse("budgets:occurrence-reconcile", args=(bill.pk,)),
        reverse("budgets:reserve-allocate", args=(budget_context.period.pk,)),
        reverse("budgets:fixed-create", args=(budget_context.period.pk,)),
    )
    for url in form_urls:
        assert client.get(url).status_code == 200

    created = client.post(
        reverse("budgets:variable-create", args=(budget_context.period.pk,)),
        {
            "category": str(budget_context.category.pk),
            "planned_amount": "30.00",
            "notes": "Created through the web form",
        },
    )
    assert created.status_code == 302
    variable_budget = VariableBudget.objects.get(
        pay_period=budget_context.period,
        category=budget_context.category,
    )

    edit_url = reverse("budgets:variable-edit", args=(variable_budget.pk,))
    assert client.get(edit_url).status_code == 200
    edited = client.post(
        edit_url,
        {
            "planned_amount": "35.00",
            "notes": "Edited through the web form",
        },
    )
    assert edited.status_code == 302
    variable_budget.refresh_from_db()
    assert variable_budget.planned_amount == Decimal("35.00")

    category_response = client.post(
        reverse("budgets:category-create", args=(budget_context.period.pk,)),
        {"name": "Dining", "color": "#8B5CF6", "sort_order": "20"},
    )
    assert category_response.status_code == 302
    assert Category.objects.filter(household=budget_context.household, name="Dining").exists()
