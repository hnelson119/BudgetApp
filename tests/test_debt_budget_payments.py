from __future__ import annotations

from dataclasses import replace
from datetime import date
from decimal import Decimal
from io import StringIO
from unittest.mock import patch

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.management import call_command
from django.core.management.base import CommandError
from django.utils import timezone

from audit.services import verify_household_chain
from budgets.services.summary import build_period_summary
from debts.models import DebtAccount, DebtTermsRevision
from debts.services import (
    DebtStatementSpec,
    DebtTermsSpec,
    MortgageInstallmentSpec,
    MortgagePlanSpec,
    change_debt_status,
    create_debt_account,
    create_mortgage_plan,
    preview_mortgage_plan,
    reconcile_debt_statement,
    revise_debt_terms,
)
from debts.services.payments import synchronize_debt_payment
from households.models import Household, HouseholdMembership
from identity.models import User
from ledger.models import JournalEntry
from periods.models import PayPeriod
from schedules.models import Occurrence, RecurringSource
from schedules.recurrence import BusinessDayAdjustment, Frequency, RecurrenceRule
from schedules.services import (
    RevisionSpec,
    create_recurring_source,
    preview_revision,
    synchronize_occurrences,
)

TODAY = date(2026, 10, 6)


@pytest.fixture
def context(db: object, monkeypatch: pytest.MonkeyPatch) -> tuple[Household, User]:
    monkeypatch.setattr(timezone, "localdate", lambda **kwargs: TODAY)
    household = Household.objects.create(name="Payment planning household")
    actor = User.objects.create_user(email="payment-planner@example.com")
    HouseholdMembership.objects.create(household=household, user=actor)
    return household, actor


def _period(household: Household, actor: User, start: date, end: date) -> PayPeriod:
    return PayPeriod.objects.create(
        household=household, start_date=start, next_start_date=end, created_by=actor
    )


def _terms(day: int = 13) -> DebtTermsSpec:
    return DebtTermsSpec(
        effective_from=TODAY,
        annual_percentage_rate=Decimal("7.0000"),
        interest_method=DebtTermsRevision.InterestMethod.MONTHLY,
        day_count_basis=DebtTermsRevision.DayCountBasis.ACTUAL_365,
        minimum_payment=Decimal("45.00"),
        recurring_extra_payment=Decimal("5.00"),
        due_day=day,
    )


def _debt(
    household: Household, actor: User, *, day: int = 13, mortgage: bool = False
) -> DebtAccount:
    debt, _ = create_debt_account(
        household=household,
        actor=actor,
        name=f"Example debt due {day}",
        debt_type=DebtAccount.DebtType.MORTGAGE if mortgage else DebtAccount.DebtType.CREDIT_CARD,
        opening_balance=Decimal("1000.00"),
        terms=_terms(day),
        request_id="payment-test-create",
    )
    return debt


def _sync(household: Household, actor: User, start: date, end: date) -> None:
    synchronize_occurrences(
        household=household,
        actor=actor,
        window_start=start,
        window_end=end,
        request_id="payment-test-generate",
    )


def test_new_unlinked_debts_are_assigned_to_each_weekly_period(
    context: tuple[Household, User],
) -> None:
    household, actor = context
    first = _period(household, actor, date(2026, 10, 8), date(2026, 10, 15))
    second = _period(household, actor, date(2026, 10, 15), date(2026, 10, 22))
    _debt(household, actor, day=13)
    _debt(household, actor, day=18)
    _debt(household, actor, day=20)
    assert list(first.occurrences.values_list("expected_date", "planned_amount")) == [
        (date(2026, 10, 13), Decimal("50.00"))
    ]
    assert second.occurrences.count() == 2
    assert build_period_summary(
        household=household, period=first, today=TODAY
    ).planned_debt_payments == Decimal("50.00")
    assert build_period_summary(
        household=household, period=second, today=TODAY
    ).planned_debt_payments == Decimal("100.00")
    assert not JournalEntry.objects.exists()
    assert verify_household_chain(household).valid


def test_debt_added_before_income_periods_generates_later_and_clamps_month_end(
    context: tuple[Household, User],
) -> None:
    household, actor = context
    _debt(household, actor, day=31)
    assert not Occurrence.objects.exists()
    period = _period(household, actor, date(2027, 2, 25), date(2027, 3, 4))
    _sync(household, actor, period.start_date, period.display_end_date)
    payment = period.occurrences.get()
    assert payment.expected_date == date(2027, 2, 28)  # Sunday remains the lender's due date.
    assert payment.planned_amount == Decimal("50.00")


def test_repair_is_idempotent_dry_run_safe_and_does_not_add_closed_history(
    context: tuple[Household, User],
) -> None:
    household, actor = context
    closed = _period(household, actor, date(2026, 9, 8), date(2026, 9, 15))
    closed.status = PayPeriod.Status.CLOSED
    closed.save()
    period = _period(household, actor, date(2026, 10, 8), date(2026, 10, 15))
    with patch("debts.services.accounts.synchronize_debt_payment"):
        _debt(household, actor)
    output = StringIO()
    call_command("sync_debt_payments", stdout=output)
    assert not RecurringSource.objects.exists()
    call_command("sync_debt_payments", apply=True, stdout=output)
    original = list(period.occurrences.values_list("pk", "planned_amount", "expected_date"))
    call_command("sync_debt_payments", apply=True, stdout=output)
    assert list(period.occurrences.values_list("pk", "planned_amount", "expected_date")) == original
    assert len(original) == 1
    assert RecurringSource.objects.count() == 1
    assert not closed.occurrences.exists()
    assert "Example debt" not in output.getvalue()
    assert "50.00" not in output.getvalue()


def test_revised_terms_replace_future_payments_preserving_closed_rows(
    context: tuple[Household, User],
) -> None:
    household, actor = context
    closed = _period(household, actor, date(2026, 10, 8), date(2026, 10, 15))
    future = _period(household, actor, date(2026, 11, 12), date(2026, 11, 19))
    debt = _debt(household, actor)
    old_closed = closed.occurrences.get()
    closed.status = PayPeriod.Status.CLOSED
    closed.save()
    revise_debt_terms(
        debt=debt,
        actor=actor,
        terms=replace(
            _terms(), effective_from=date(2026, 10, 7), due_day=14, minimum_payment=Decimal("70.00")
        ),
        reason="Revised lender payment",
        request_id="payment-test-revise",
    )
    old_closed.refresh_from_db()
    assert old_closed.status == Occurrence.Status.SCHEDULED
    assert old_closed.planned_amount == Decimal("50.00")
    assert closed.occurrences.count() == 1
    payment = future.occurrences.get(status=Occurrence.Status.SCHEDULED)
    assert payment.expected_date == date(2026, 11, 14)
    assert payment.planned_amount == Decimal("75.00")
    assert not JournalEntry.objects.exists()


@pytest.mark.parametrize(
    "status",
    [
        Occurrence.Status.OVERRIDDEN,
        Occurrence.Status.MOVED,
        Occurrence.Status.COMPLETED,
        Occurrence.Status.CANCELLED,
    ],
)
def test_terms_changes_do_not_duplicate_protected_monthly_payments(
    context: tuple[Household, User], status: str
) -> None:
    household, actor = context
    period = _period(household, actor, date(2026, 10, 8), date(2026, 10, 15))
    debt = _debt(household, actor)
    protected = period.occurrences.get()
    protected.status = status
    protected.save(update_fields=("status",))
    revise_debt_terms(
        debt=debt,
        actor=actor,
        terms=replace(_terms(), effective_from=date(2026, 10, 7), due_day=14),
        reason="Keep recorded payment",
        request_id="payment-test-protected",
    )
    protected.refresh_from_db()
    assert protected.status == status
    assert period.occurrences.count() == 1


def test_archive_and_statement_payoff_remove_future_payments_without_posting(
    context: tuple[Household, User],
) -> None:
    household, actor = context
    period = _period(household, actor, date(2026, 10, 8), date(2026, 10, 15))
    debt = _debt(household, actor)
    change_debt_status(
        debt=debt,
        actor=actor,
        status=DebtAccount.Status.ARCHIVED,
        reason="Archive debt",
        request_id="payment-test-archive",
    )
    assert not period.occurrences.exists()
    change_debt_status(
        debt=debt,
        actor=actor,
        status=DebtAccount.Status.ACTIVE,
        reason="Restore debt",
        request_id="payment-test-restore",
    )
    assert period.occurrences.count() == 1
    reconcile_debt_statement(
        debt=debt,
        actor=actor,
        statement=DebtStatementSpec(
            statement_date=TODAY,
            statement_balance=Decimal("0.00"),
            annual_percentage_rate=Decimal("7.0000"),
            minimum_payment=Decimal("0.00"),
        ),
        request_id="payment-test-payoff",
    )
    assert not period.occurrences.exists()
    assert not JournalEntry.objects.exists()


def test_split_mortgage_replaces_monthly_default_from_its_effective_date(
    context: tuple[Household, User],
) -> None:
    household, actor = context
    period = _period(household, actor, date(2026, 10, 8), date(2026, 10, 15))
    debt = _debt(household, actor, mortgage=True)
    default = period.occurrences.get()
    spec = MortgagePlanSpec(
        effective_from=TODAY,
        monthly_obligation=Decimal("50.00"),
        principal_and_interest=Decimal("45.00"),
        escrow=Decimal("5.00"),
        pmi=Decimal("0.00"),
        fees=Decimal("0.00"),
        recurring_extra_principal=Decimal("0.00"),
        statement_cycle_day=13,
        installments=(
            MortgageInstallmentSpec(Decimal("25.00"), 10),
            MortgageInstallmentSpec(Decimal("25.00"), 13),
        ),
        adjustment_policy=BusinessDayAdjustment.NONE,
    )
    preview = preview_mortgage_plan(spec)
    create_mortgage_plan(
        debt=debt,
        actor=actor,
        spec=spec,
        expected_preview_fingerprint=preview.fingerprint,
        request_id="payment-test-split",
    )
    default.refresh_from_db()
    assert default.status == Occurrence.Status.SUPERSEDED
    assert period.occurrences.count() == 2
    assert build_period_summary(
        household=household, period=period, today=TODAY
    ).planned_debt_payments == Decimal("50.00")


def test_split_conversion_rejects_protected_default_payments(
    context: tuple[Household, User],
) -> None:
    household, actor = context
    period = _period(household, actor, date(2026, 10, 8), date(2026, 10, 15))
    debt = _debt(household, actor, mortgage=True)
    payment = period.occurrences.get()
    payment.status = Occurrence.Status.OVERRIDDEN
    payment.save(update_fields=("status",))
    spec = MortgagePlanSpec(
        effective_from=TODAY,
        monthly_obligation=Decimal("50.00"),
        principal_and_interest=Decimal("45.00"),
        escrow=Decimal("5.00"),
        pmi=Decimal("0.00"),
        fees=Decimal("0.00"),
        recurring_extra_principal=Decimal("0.00"),
        statement_cycle_day=13,
        installments=(
            MortgageInstallmentSpec(Decimal("25.00"), 10),
            MortgageInstallmentSpec(Decimal("25.00"), 13),
        ),
        adjustment_policy=BusinessDayAdjustment.NONE,
    )
    with pytest.raises(ValidationError, match="protected monthly debt payments"):
        create_mortgage_plan(
            debt=debt,
            actor=actor,
            spec=spec,
            expected_preview_fingerprint=preview_mortgage_plan(spec).fingerprint,
            request_id="payment-test-protected-split",
        )
    assert period.occurrences.count() == 1
    assert RecurringSource.objects.count() == 1


def test_scoped_debt_sync_preserves_other_sources_and_denies_outsiders(
    context: tuple[Household, User],
) -> None:
    household, actor = context
    period = _period(household, actor, date(2026, 10, 8), date(2026, 10, 15))
    spec = RevisionSpec(
        effective_from=TODAY,
        expected_amount=Decimal("100.00"),
        rule=RecurrenceRule(Frequency.ONCE, date(2026, 10, 8)),
    )
    source, _ = create_recurring_source(
        household=household,
        actor=actor,
        kind=RecurringSource.Kind.INCOME,
        name="Example paycheck",
        revision_spec=spec,
        expected_preview_fingerprint=preview_revision(spec, preview_from=TODAY).fingerprint,
        request_id="payment-test-income",
    )
    _sync(household, actor, period.start_date, period.display_end_date)
    income = source.occurrences.get()
    snapshot = (income.pk, income.updated_at, income.planned_amount, income.pay_period_id)
    debt = _debt(household, actor)
    income.refresh_from_db()
    assert (income.pk, income.updated_at, income.planned_amount, income.pay_period_id) == snapshot
    outsider = User.objects.create_user(email="other-planner@example.com")
    with pytest.raises(PermissionDenied):
        synchronize_debt_payment(debt=debt, actor=outsider, request_id="payment-test-denied")


def test_repair_fails_atomically_when_creator_membership_is_inactive(
    context: tuple[Household, User],
) -> None:
    household, actor = context
    with patch("debts.services.accounts.synchronize_debt_payment"):
        _debt(household, actor)
    HouseholdMembership.objects.filter(household=household, user=actor).update(is_active=False)
    with pytest.raises(CommandError, match="no changes applied"):
        call_command("sync_debt_payments", apply=True)
    assert not RecurringSource.objects.exists()
