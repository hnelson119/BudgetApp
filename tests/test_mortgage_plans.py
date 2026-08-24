from __future__ import annotations

from dataclasses import replace
from datetime import date
from decimal import Decimal
from pathlib import Path

import pytest
from django.core.exceptions import PermissionDenied, ValidationError

from audit.models import AuditEvent
from debts.models import (
    DebtAccount,
    DebtTermsRevision,
    MortgagePaymentComponent,
    MortgagePaymentPlan,
    MortgagePlanRevision,
)
from debts.services import (
    DebtTermsSpec,
    MortgageInstallmentSpec,
    MortgagePlanSpec,
    PayoffStrategy,
    create_debt_account,
    create_mortgage_plan,
    preview_mortgage_plan,
    project_debt_payoff,
    projection_debts_from_accounts,
    revise_mortgage_plan,
    set_one_off_extra_principal,
)
from households.models import Household, HouseholdMembership
from identity.models import User
from periods.models import PayPeriod
from schedules.models import Occurrence, RecurringSource
from schedules.recurrence import BusinessDayAdjustment

TEST_PASSWORD = "mortgage-plan-test-password"  # pragma: allowlist secret


@pytest.fixture
def mortgage_context(db: object) -> tuple[Household, User, User, DebtAccount]:
    household = Household.objects.create(name="Mortgage Household")
    user = User.objects.create_user(email="mortgage@example.com", password=TEST_PASSWORD)
    outsider = User.objects.create_user(
        email="mortgage-outsider@example.com", password=TEST_PASSWORD
    )
    HouseholdMembership.objects.create(household=household, user=user)
    debt, _ = create_debt_account(
        household=household,
        actor=user,
        name="Home mortgage",
        debt_type=DebtAccount.DebtType.MORTGAGE,
        opening_balance=Decimal("10000.00"),
        terms=DebtTermsSpec(
            effective_from=date(2020, 1, 1),
            annual_percentage_rate=Decimal("0.0000"),
            interest_method=DebtTermsRevision.InterestMethod.MONTHLY,
            day_count_basis=DebtTermsRevision.DayCountBasis.ACTUAL_365,
            minimum_payment=Decimal("1350.00"),
            due_day=20,
        ),
        request_id="mortgage-debt-create",
    )
    for start, end in (
        (date(2026, 8, 27), date(2026, 9, 3)),
        (date(2026, 9, 3), date(2026, 9, 10)),
        (date(2026, 9, 10), date(2026, 9, 17)),
        (date(2026, 9, 17), date(2026, 9, 24)),
        (date(2026, 9, 24), date(2026, 10, 1)),
        (date(2026, 10, 1), date(2026, 10, 8)),
        (date(2026, 10, 8), date(2026, 10, 15)),
        (date(2026, 10, 15), date(2026, 10, 22)),
        (date(2026, 10, 22), date(2026, 10, 29)),
        (date(2026, 10, 29), date(2026, 11, 5)),
    ):
        PayPeriod.objects.create(
            household=household,
            start_date=start,
            next_start_date=end,
            created_by=user,
        )
    return household, user, outsider, debt


def _golden_spec(*, effective_from: date = date(2026, 9, 1)) -> MortgagePlanSpec:
    return MortgagePlanSpec(
        effective_from=effective_from,
        monthly_obligation=Decimal("1350.00"),
        principal_and_interest=Decimal("1100.00"),
        escrow=Decimal("250.00"),
        pmi=Decimal("0.00"),
        fees=Decimal("0.00"),
        recurring_extra_principal=Decimal("0.00"),
        statement_cycle_day=20,
        installments=(
            MortgageInstallmentSpec(Decimal("675.00"), 5),
            MortgageInstallmentSpec(Decimal("675.00"), 20),
        ),
        adjustment_policy=BusinessDayAdjustment.PREVIOUS,
    )


def _create_plan(debt: DebtAccount, user: User) -> MortgagePaymentPlan:
    spec = _golden_spec()
    mutation = create_mortgage_plan(
        debt=debt,
        actor=user,
        spec=spec,
        expected_preview_fingerprint=preview_mortgage_plan(spec).fingerprint,
        request_id="mortgage-plan-create",
    )
    return mutation.plan


@pytest.mark.django_db
def test_golden_h_plan_creates_two_due_date_assigned_installments_and_components(
    mortgage_context: tuple[Household, User, User, DebtAccount],
) -> None:
    household, user, _, debt = mortgage_context
    plan = _create_plan(debt, user)

    revision = plan.revisions.get()
    components = {value.component_type: value.amount for value in revision.components.all()}
    assert revision.monthly_obligation == Decimal("1350.00")
    assert components[MortgagePaymentComponent.ComponentType.PRINCIPAL_INTEREST] == Decimal(
        "1100.00"
    )
    assert components[MortgagePaymentComponent.ComponentType.ESCROW] == Decimal("250.00")
    rules = tuple(revision.installment_rules.order_by("installment_order"))
    assert tuple(value.amount for value in rules) == (
        Decimal("675.00"),
        Decimal("675.00"),
    )
    assert (
        RecurringSource.objects.filter(
            household=household, kind=RecurringSource.Kind.DEBT_PAYMENT
        ).count()
        == 2
    )
    september = tuple(
        Occurrence.objects.filter(
            source__mortgage_installment_rules__plan_revision=revision,
            expected_date__month=9,
        )
        .distinct()
        .order_by("expected_date")
    )
    assert tuple(value.expected_date for value in september) == (
        date(2026, 9, 4),
        date(2026, 9, 18),
    )
    assert tuple(value.pay_period.start_date for value in september if value.pay_period) == (
        date(2026, 9, 3),
        date(2026, 9, 17),
    )
    assert AuditEvent.objects.filter(action="mortgage.plan_created").exists()


@pytest.mark.django_db
def test_one_off_extra_changes_period_and_projection_but_not_future_schedule(
    mortgage_context: tuple[Household, User, User, DebtAccount],
) -> None:
    _, user, _, debt = mortgage_context
    plan = _create_plan(debt, user)
    revision = plan.revisions.get()
    source = revision.installment_rules.get(installment_order=2).source
    september = source.occurrences.get(expected_date=date(2026, 9, 18))
    october = source.occurrences.get(expected_date=date(2026, 10, 20))

    updated = set_one_off_extra_principal(
        occurrence=september,
        actor=user,
        extra_principal=Decimal("100.00"),
        request_id="mortgage-one-off",
        reason="Use this period's excess",
    )
    october.refresh_from_db()
    assert updated.status == Occurrence.Status.OVERRIDDEN
    assert updated.planned_amount == Decimal("775.00")
    assert updated.generated_amount == Decimal("675.00")
    assert october.planned_amount == Decimal("675.00")
    assert source.revisions.count() == 1

    projected_debt = projection_debts_from_accounts((debt,))[0]
    assert projected_debt.terms[-1].minimum_payment == Decimal("1100.00")
    assert projected_debt.one_time_extra_payments[0].amount == Decimal("100.00")
    projection = project_debt_payoff(
        (projected_debt,),
        strategy=PayoffStrategy.MINIMUM_ONLY,
        monthly_extra=Decimal("0.00"),
        start_date=date(2026, 9, 1),
        max_months=1,
    )
    payment = projection.cycles[0].payments[0]
    assert payment.minimum_payment == Decimal("1100.00")
    assert payment.one_time_extra_payment == Decimal("100.00")
    assert payment.closing_balance == Decimal("8800.00")
    assert AuditEvent.objects.filter(action="mortgage.extra_principal_planned").exists()


@pytest.mark.django_db
def test_revision_appends_history_and_preserves_protected_occurrence(
    mortgage_context: tuple[Household, User, User, DebtAccount],
) -> None:
    _, user, _, debt = mortgage_context
    plan = _create_plan(debt, user)
    source = plan.revisions.get().installment_rules.get(installment_order=1).source
    protected = source.occurrences.get(expected_date=date(2026, 9, 4))
    set_one_off_extra_principal(
        occurrence=protected,
        actor=user,
        extra_principal=Decimal("100.00"),
        request_id="mortgage-protect-before-revision",
        reason="Keep this period's extra",
    )
    revised_spec = replace(
        _golden_spec(effective_from=date(2026, 10, 1)),
        monthly_obligation=Decimal("1400.00"),
        principal_and_interest=Decimal("1150.00"),
        installments=(
            MortgageInstallmentSpec(Decimal("700.00"), 5),
            MortgageInstallmentSpec(Decimal("700.00"), 20),
        ),
    )
    revised = revise_mortgage_plan(
        plan=plan,
        actor=user,
        spec=revised_spec,
        expected_preview_fingerprint=preview_mortgage_plan(revised_spec, plan=plan).fingerprint,
        request_id="mortgage-plan-revise",
        reason="Servicer changed escrow",
    )

    protected.refresh_from_db()
    assert revised.revision.revision_number == 2
    assert plan.revisions.count() == 2
    assert source.revisions.count() == 2
    assert protected.status == Occurrence.Status.OVERRIDDEN
    assert protected.planned_amount == Decimal("775.00")
    assert AuditEvent.objects.filter(action="mortgage.plan_revised").exists()


@pytest.mark.django_db
def test_plan_validation_membership_and_immutable_records_fail_closed(
    mortgage_context: tuple[Household, User, User, DebtAccount],
) -> None:
    _, user, outsider, debt = mortgage_context
    invalid_specs = (
        replace(_golden_spec(), installments=(_golden_spec().installments[0],)),
        replace(_golden_spec(), escrow=Decimal("200.00")),
        replace(
            _golden_spec(),
            installments=(
                MortgageInstallmentSpec(Decimal("600.00"), 5),
                MortgageInstallmentSpec(Decimal("675.00"), 20),
            ),
        ),
    )
    for invalid in invalid_specs:
        with pytest.raises(ValidationError):
            preview_mortgage_plan(invalid)  # type: ignore[arg-type]
    with pytest.raises(PermissionDenied):
        create_mortgage_plan(
            debt=debt,
            actor=outsider,
            spec=_golden_spec(),
            expected_preview_fingerprint=preview_mortgage_plan(_golden_spec()).fingerprint,
            request_id="mortgage-outsider",
        )
    plan = _create_plan(debt, user)
    revision = plan.revisions.get()
    revision.monthly_obligation = Decimal("1.00")
    with pytest.raises(ValidationError, match="cannot be updated"):
        revision.save()
    with pytest.raises(ValidationError, match="cannot be deleted"):
        MortgagePlanRevision.objects.filter(pk=revision.pk).delete()


def test_postgresql_migration_protects_every_mortgage_history_table() -> None:
    migration = (
        Path(__file__).parents[1]
        / "debts"
        / "migrations"
        / "0004_postgresql_protect_mortgage_history.py"
    ).read_text(encoding="utf-8")
    for table in (
        "debts_mortgagepaymentplan",
        "debts_mortgageplanrevision",
        "debts_mortgagepaymentcomponent",
        "debts_mortgageinstallmentrule",
    ):
        assert table in migration
    assert "BEFORE UPDATE OR DELETE" in migration
    assert "BEFORE TRUNCATE" in migration
