from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date, datetime, time
from decimal import Decimal
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.utils import timezone

from audit.models import AuditEvent
from budgets.services import build_period_summary
from debts.models import DebtAccount, DebtTermsRevision
from debts.services import DebtTermsSpec, create_debt_account
from goals.models import Goal, GoalContribution, GoalRevision
from goals.services import (
    GoalSpec,
    allocate_reserve_by_priority,
    allocate_reserve_to_goal,
    create_goal,
    goal_current_amount,
    goal_progress_rows,
    preview_goal,
    preview_priority_allocation,
    preview_reserve_allocation,
    record_goal_contribution,
    revise_goal,
)
from households.models import Household, HouseholdMembership
from identity.models import User
from ledger.models import FinancialAccount, JournalEntry
from ledger.services import create_financial_account
from periods.models import PayPeriod
from periods.services import close_period
from reserves.models import ReserveEntry
from reserves.services import reserve_balance
from schedules.models import Occurrence, RecurringSource
from schedules.services import override_occurrence

TEST_PASSWORD = "goals-test-password"  # pragma: allowlist secret


@dataclass(frozen=True, slots=True)
class GoalContext:
    household: Household
    user: User
    outsider: User
    periods: tuple[PayPeriod, ...]
    checking: FinancialAccount
    savings: FinancialAccount
    investing: FinancialAccount


@pytest.fixture
def goal_context(db: object) -> GoalContext:
    household = Household.objects.create(name="Goal Household")
    user = User.objects.create_user(email="goals@example.com", password=TEST_PASSWORD)
    outsider = User.objects.create_user(email="goals-outsider@example.com", password=TEST_PASSWORD)
    HouseholdMembership.objects.create(household=household, user=user)
    periods = tuple(
        PayPeriod.objects.create(
            household=household,
            start_date=start,
            next_start_date=end,
            status=PayPeriod.Status.OPEN,
            created_by=user,
        )
        for start, end in (
            (date(2026, 8, 20), date(2026, 8, 27)),
            (date(2026, 8, 27), date(2026, 9, 3)),
            (date(2026, 9, 3), date(2026, 9, 10)),
            (date(2026, 9, 10), date(2026, 9, 17)),
        )
    )
    checking = create_financial_account(
        household=household,
        actor=user,
        name="Checking",
        account_type=FinancialAccount.AccountType.CHECKING,
        classification=FinancialAccount.Classification.ASSET,
        request_id="goal-account-checking",
    )
    savings = create_financial_account(
        household=household,
        actor=user,
        name="Savings",
        account_type=FinancialAccount.AccountType.SAVINGS,
        classification=FinancialAccount.Classification.ASSET,
        request_id="goal-account-savings",
    )
    investing = create_financial_account(
        household=household,
        actor=user,
        name="Investing",
        account_type=FinancialAccount.AccountType.OTHER,
        classification=FinancialAccount.Classification.ASSET,
        request_id="goal-account-investing",
    )
    return GoalContext(household, user, outsider, periods, checking, savings, investing)


def _spec(
    context: GoalContext,
    *,
    name: str = "Emergency Fund",
    effective_from: date = date(2026, 8, 20),
    goal_type: str = GoalRevision.GoalType.SAVINGS,
    target: str = "5000.00",
    contribution: str = "100.00",
    priority: int = 1,
    automatic: bool = False,
    destination: FinancialAccount | None = None,
    debt: DebtAccount | None = None,
) -> GoalSpec:
    return GoalSpec(
        effective_from=effective_from,
        name=name,
        goal_type=goal_type,
        target_amount=Decimal(target),
        target_date=date(2027, 8, 20),
        contribution_per_period=Decimal(contribution),
        priority=priority,
        status=GoalRevision.Status.ACTIVE,
        automatic_excess_allocation=automatic,
        source_account=context.checking,
        destination_account=(destination or context.savings) if debt is None else None,
        linked_debt=debt,
        notes="Protected household goal",
    )


def _create(
    context: GoalContext,
    spec: GoalSpec | None = None,
    *,
    opening: str = "0.00",
    request_id: str = "goal-create-emergency",
) -> Goal:
    specification = spec or _spec(context)
    preview = preview_goal(
        household=context.household,
        spec=specification,
        opening_amount=Decimal(opening),
    )
    goal, _ = create_goal(
        household=context.household,
        actor=context.user,
        spec=specification,
        opening_amount=Decimal(opening),
        expected_preview_fingerprint=preview.fingerprint,
        request_id=request_id,
    )
    return goal


def _effective(value: date) -> datetime:
    return timezone.make_aware(
        datetime.combine(value, time(hour=12)),
        ZoneInfo("America/New_York"),
    )


def _visa_debt(context: GoalContext) -> DebtAccount:
    liability = create_financial_account(
        household=context.household,
        actor=context.user,
        name="Visa liability",
        account_type=FinancialAccount.AccountType.CREDIT_CARD,
        classification=FinancialAccount.Classification.LIABILITY,
        request_id="goal-account-visa",
    )
    debt, _ = create_debt_account(
        household=context.household,
        actor=context.user,
        name="Visa",
        debt_type=DebtAccount.DebtType.CREDIT_CARD,
        opening_balance=Decimal("1200.00"),
        terms=DebtTermsSpec(
            effective_from=date(2026, 8, 20),
            annual_percentage_rate=Decimal("19.9900"),
            interest_method=DebtTermsRevision.InterestMethod.MONTHLY,
            day_count_basis=DebtTermsRevision.DayCountBasis.ACTUAL_365,
            minimum_payment=Decimal("50.00"),
            due_day=15,
        ),
        financial_account=liability,
        request_id="goal-debt-visa-create",
    )
    return debt


@pytest.mark.django_db
def test_goal_schedule_follows_paycheck_period_boundaries_and_defaults_safe(
    goal_context: GoalContext,
) -> None:
    goal = _create(goal_context, opening="250.00")
    revision = goal.revisions.get()
    plan = goal.funding_plan
    occurrences = tuple(plan.source.occurrences.order_by("nominal_date"))

    assert revision.automatic_excess_allocation is False
    assert revision.contribution_per_period == Decimal("100.00")
    assert plan.source.kind == RecurringSource.Kind.GOAL_CONTRIBUTION
    assert tuple(item.nominal_date for item in occurrences) == tuple(
        period.start_date for period in goal_context.periods
    )
    assert all(
        item.pay_period_id == period.pk
        for item, period in zip(occurrences, goal_context.periods, strict=True)
    )
    assert AuditEvent.objects.filter(action="goal.created", entity_id=str(goal.pk)).exists()


@pytest.mark.django_db
def test_goal_revision_pauses_future_schedule_without_overwriting_override(
    goal_context: GoalContext,
) -> None:
    goal = _create(goal_context)
    occurrences = tuple(goal.funding_plan.source.occurrences.order_by("nominal_date"))
    protected = override_occurrence(
        occurrence=occurrences[1],
        actor=goal_context.user,
        request_id="goal-override-future",
        reason="One-off larger contribution",
        planned_amount=Decimal("175.00"),
    )
    paused_spec = replace(
        _spec(goal_context, effective_from=date(2026, 8, 27)),
        status=GoalRevision.Status.PAUSED,
    )
    preview = preview_goal(household=goal_context.household, spec=paused_spec)
    revise_goal(
        goal=goal,
        actor=goal_context.user,
        spec=paused_spec,
        expected_preview_fingerprint=preview.fingerprint,
        request_id="goal-pause-revision",
        reason="Temporarily redirecting cash",
    )

    protected.refresh_from_db()
    occurrences[2].refresh_from_db()
    assert protected.status == Occurrence.Status.OVERRIDDEN
    assert protected.planned_amount == Decimal("175.00")
    assert occurrences[2].status == Occurrence.Status.SUPERSEDED
    assert goal.revisions.count() == 2


@pytest.mark.django_db
def test_scheduled_contribution_records_transfer_not_income_or_spending(
    goal_context: GoalContext,
) -> None:
    goal = _create(goal_context, opening="250.00")
    occurrence = goal.funding_plan.source.occurrences.order_by("nominal_date").first()
    assert occurrence is not None and occurrence.pay_period is not None

    contribution = record_goal_contribution(
        goal=goal,
        actor=goal_context.user,
        pay_period=occurrence.pay_period,
        amount=Decimal("100.00"),
        effective_at=_effective(occurrence.expected_date),
        request_id="goal-scheduled-actual",
        reason="Paycheck contribution",
        contribution_type=GoalContribution.ContributionType.SCHEDULED,
        occurrence=occurrence,
    )

    occurrence.refresh_from_db()
    assert contribution.journal_entry.entry_type == JournalEntry.EntryType.GOAL_CONTRIBUTION
    assert contribution.journal_entry.category_id is None
    assert occurrence.status == Occurrence.Status.COMPLETED
    assert occurrence.actual_amount == Decimal("100.00")
    assert goal_current_amount(goal) == Decimal("350.00")
    assert not JournalEntry.objects.filter(
        household=goal_context.household,
        entry_type__in=(JournalEntry.EntryType.INCOME, JournalEntry.EntryType.EXPENSE),
    ).exists()


@pytest.mark.django_db
def test_golden_c_reserve_allocations_fund_savings_and_debt_without_new_income(
    goal_context: GoalContext,
) -> None:
    first, posting = goal_context.periods[:2]
    close_period(
        pay_period=first,
        actor=goal_context.user,
        closing_surplus=Decimal("929.90"),
        request_id="goal-golden-close-period",
    )
    emergency = _create(
        goal_context,
        _spec(goal_context, effective_from=posting.start_date, contribution="0.00"),
        request_id="goal-golden-emergency",
    )
    visa = _visa_debt(goal_context)
    payoff = _create(
        goal_context,
        _spec(
            goal_context,
            name="Visa payoff",
            effective_from=posting.start_date,
            goal_type=GoalRevision.GoalType.DEBT_PAYOFF,
            target="1200.00",
            contribution="0.00",
            priority=2,
            debt=visa,
        ),
        request_id="goal-golden-visa-payoff",
    )

    emergency_preview = preview_reserve_allocation(
        goal=emergency,
        posting_period=posting,
        amount=Decimal("300.00"),
    )
    emergency_contribution = allocate_reserve_to_goal(
        goal=emergency,
        actor=goal_context.user,
        posting_period=posting,
        amount=Decimal("300.00"),
        expected_preview_fingerprint=emergency_preview.fingerprint,
        request_id="goal-golden-emergency-allocation",
        reason="Build emergency savings",
    )
    payoff_preview = preview_reserve_allocation(
        goal=payoff,
        posting_period=posting,
        amount=Decimal("100.00"),
    )
    payoff_contribution = allocate_reserve_to_goal(
        goal=payoff,
        actor=goal_context.user,
        posting_period=posting,
        amount=Decimal("100.00"),
        expected_preview_fingerprint=payoff_preview.fingerprint,
        request_id="goal-golden-visa-allocation",
        reason="Extra Visa principal",
    )

    assert reserve_balance(goal_context.household) == Decimal("529.90")
    assert goal_current_amount(emergency) == Decimal("300.00")
    assert goal_current_amount(payoff) == Decimal("100.00")
    assert (
        emergency_contribution.journal_entry.entry_type == JournalEntry.EntryType.GOAL_CONTRIBUTION
    )
    assert payoff_contribution.journal_entry.entry_type == JournalEntry.EntryType.DEBT_PAYMENT
    assert (
        ReserveEntry.objects.filter(
            household=goal_context.household,
            entry_type=ReserveEntry.EntryType.EXPLICIT_ALLOCATION,
        ).count()
        == 2
    )
    assert (
        JournalEntry.objects.filter(
            household=goal_context.household,
            entry_type=JournalEntry.EntryType.INCOME,
        ).count()
        == 0
    )
    assert not JournalEntry.objects.filter(
        household=goal_context.household,
        category__isnull=False,
    ).exists()
    assert AuditEvent.objects.filter(action="goal.contribution_recorded").count() == 2
    summary = build_period_summary(
        household=goal_context.household,
        period=posting,
        today=posting.start_date,
    )
    assert summary.actual_goal_contributions == Decimal("0.00")
    assert summary.actual_debt_payments == Decimal("0.00")
    assert summary.projected_closing_surplus == Decimal("0.00")


@pytest.mark.django_db
def test_priority_allocation_uses_only_opted_in_active_goals_in_order(
    goal_context: GoalContext,
) -> None:
    first, posting = goal_context.periods[:2]
    close_period(
        pay_period=first,
        actor=goal_context.user,
        closing_surplus=Decimal("250.00"),
        request_id="goal-priority-close-period",
    )
    first_goal = _create(
        goal_context,
        _spec(
            goal_context,
            name="First goal",
            effective_from=posting.start_date,
            target="150.00",
            contribution="0.00",
            priority=1,
            automatic=True,
        ),
        request_id="goal-priority-first-create",
    )
    second_goal = _create(
        goal_context,
        _spec(
            goal_context,
            name="Second goal",
            effective_from=posting.start_date,
            target="200.00",
            contribution="0.00",
            priority=2,
            automatic=True,
            destination=goal_context.investing,
        ),
        request_id="goal-priority-second-create",
    )
    _create(
        goal_context,
        _spec(
            goal_context,
            name="Opted out",
            effective_from=posting.start_date,
            target="100.00",
            contribution="0.00",
            priority=0 + 1,
            automatic=False,
        ),
        request_id="goal-priority-opted-out",
    )
    preview = preview_priority_allocation(
        household=goal_context.household,
        posting_period=posting,
        amount=Decimal("200.00"),
    )
    contributions = allocate_reserve_by_priority(
        household=goal_context.household,
        actor=goal_context.user,
        posting_period=posting,
        amount=Decimal("200.00"),
        expected_preview_fingerprint=preview.fingerprint,
        request_id="goal-priority-allocation",
        reason="Confirmed priority allocation",
    )

    assert tuple(item.goal_id for item in contributions) == (first_goal.pk, second_goal.pk)
    assert tuple(item.amount for item in contributions) == (
        Decimal("150.00"),
        Decimal("50.00"),
    )
    assert reserve_balance(goal_context.household) == Decimal("50.00")


@pytest.mark.django_db
def test_goal_services_enforce_membership_stale_previews_and_immutable_history(
    goal_context: GoalContext,
) -> None:
    spec = _spec(goal_context)
    preview = preview_goal(
        household=goal_context.household,
        spec=spec,
        opening_amount=Decimal("0.00"),
    )
    with pytest.raises(PermissionDenied):
        create_goal(
            household=goal_context.household,
            actor=goal_context.outsider,
            spec=spec,
            opening_amount=Decimal("0.00"),
            expected_preview_fingerprint=preview.fingerprint,
            request_id="goal-outsider-create",
        )
    with pytest.raises(ValidationError, match="stale"):
        create_goal(
            household=goal_context.household,
            actor=goal_context.user,
            spec=replace(spec, target_amount=Decimal("6000.00")),
            opening_amount=Decimal("0.00"),
            expected_preview_fingerprint=preview.fingerprint,
            request_id="goal-stale-create",
        )
    goal = _create(goal_context)
    goal.opening_amount = Decimal("10.00")
    with pytest.raises(ValidationError, match="cannot be updated"):
        goal.save()
    with pytest.raises(ValidationError, match="cannot be updated"):
        Goal.objects.filter(pk=goal.pk).update(opening_amount=Decimal("10.00"))
    with pytest.raises(ValidationError, match="cannot be deleted"):
        Goal.objects.filter(pk=goal.pk).delete()


def test_postgresql_goal_history_migration_protects_every_goal_table() -> None:
    migration = Path("goals/migrations/0002_postgresql_protect_history.py").read_text()
    for table in (
        "goals_goal",
        "goals_goalrevision",
        "goals_goalfundingplan",
        "goals_goalcontribution",
    ):
        assert table in migration
    assert "BEFORE UPDATE OR DELETE" in migration
    assert "BEFORE TRUNCATE" in migration
    assert "session_user" in migration


@pytest.mark.django_db
def test_goal_progress_projection_uses_future_paycheck_boundaries(
    goal_context: GoalContext,
) -> None:
    goal = _create(
        goal_context,
        _spec(goal_context, target="250.00", contribution="100.00"),
        opening="50.00",
    )
    rows = goal_progress_rows(household=goal_context.household, on_date=date(2026, 8, 20))
    row = next(item for item in rows if item.goal == goal)
    assert row.remaining_amount == Decimal("200.00")
    assert row.progress_percent == Decimal("20.00")
    assert row.projected_completion_date == date(2026, 8, 27)


@pytest.mark.django_db
def test_goal_spec_validation_rejects_invalid_types_accounts_dates_and_amounts(
    goal_context: GoalContext,
) -> None:
    valid = _spec(goal_context)
    invalid_specs = (
        replace(valid, name=" "),
        replace(valid, goal_type="unknown"),
        replace(valid, status="unknown"),
        replace(valid, priority=0),
        replace(valid, target_amount=Decimal("0.00")),
        replace(valid, target_amount=Decimal("100.001")),
        replace(valid, target_date=date(2026, 8, 19)),
        replace(valid, destination_account=goal_context.checking),
        replace(valid, destination_account=None),
    )
    for spec in invalid_specs:
        with pytest.raises(ValidationError):
            preview_goal(household=goal_context.household, spec=spec)
    with pytest.raises(ValidationError, match="Opening progress"):
        preview_goal(
            household=goal_context.household,
            spec=valid,
            opening_amount=Decimal("6000.00"),
        )

    liability_source = create_financial_account(
        household=goal_context.household,
        actor=goal_context.user,
        name="Invalid source card",
        account_type=FinancialAccount.AccountType.CREDIT_CARD,
        classification=FinancialAccount.Classification.LIABILITY,
        request_id="goal-invalid-source-card",
    )
    with pytest.raises(ValidationError, match="source account"):
        preview_goal(
            household=goal_context.household,
            spec=replace(valid, source_account=liability_source),
        )

    other_household = Household.objects.create(name="Other goal household")
    HouseholdMembership.objects.create(household=other_household, user=goal_context.outsider)
    other_source = create_financial_account(
        household=other_household,
        actor=goal_context.outsider,
        name="Other checking",
        account_type=FinancialAccount.AccountType.CHECKING,
        classification=FinancialAccount.Classification.ASSET,
        request_id="goal-other-source",
    )
    other_destination = create_financial_account(
        household=other_household,
        actor=goal_context.outsider,
        name="Other savings",
        account_type=FinancialAccount.AccountType.SAVINGS,
        classification=FinancialAccount.Classification.ASSET,
        request_id="goal-other-destination",
    )
    with pytest.raises(ValidationError, match="destination account"):
        preview_goal(
            household=goal_context.household,
            spec=replace(valid, destination_account=other_destination),
        )
    with pytest.raises(ValidationError, match="Generate paycheck periods"):
        preview_goal(
            household=other_household,
            spec=replace(
                valid,
                source_account=other_source,
                destination_account=other_destination,
            ),
        )


@pytest.mark.django_db
def test_goal_contribution_and_reserve_guards_fail_closed(goal_context: GoalContext) -> None:
    goal = _create(goal_context)
    period = goal_context.periods[0]
    with pytest.raises(ValidationError, match="outside"):
        record_goal_contribution(
            goal=goal,
            actor=goal_context.user,
            pay_period=period,
            amount=Decimal("25.00"),
            effective_at=_effective(date(2026, 8, 27)),
            request_id="goal-invalid-date",
            reason="Wrong period",
        )
    with pytest.raises(ValidationError, match="Scheduled contributions"):
        record_goal_contribution(
            goal=goal,
            actor=goal_context.user,
            pay_period=period,
            amount=Decimal("25.00"),
            effective_at=_effective(period.start_date),
            request_id="goal-missing-occurrence",
            reason="Missing schedule link",
            contribution_type=GoalContribution.ContributionType.SCHEDULED,
        )

    close_period(
        pay_period=period,
        actor=goal_context.user,
        closing_surplus=Decimal("100.00"),
        request_id="goal-guard-close-period",
    )
    posting = goal_context.periods[1]
    preview = preview_reserve_allocation(
        goal=goal,
        posting_period=posting,
        amount=Decimal("25.00"),
    )
    with pytest.raises(ValidationError, match="require a reason"):
        allocate_reserve_to_goal(
            goal=goal,
            actor=goal_context.user,
            posting_period=posting,
            amount=Decimal("25.00"),
            expected_preview_fingerprint=preview.fingerprint,
            request_id="goal-reserve-no-reason",
            reason="",
        )
    with pytest.raises(ValidationError, match="not eligible"):
        allocate_reserve_to_goal(
            goal=goal,
            actor=goal_context.user,
            posting_period=posting,
            amount=Decimal("25.00"),
            expected_preview_fingerprint=preview.fingerprint,
            request_id="goal-reserve-auto-disabled",
            reason="Should not be automatic",
            automatic=True,
        )
    with pytest.raises(ValidationError, match="stale"):
        allocate_reserve_to_goal(
            goal=goal,
            actor=goal_context.user,
            posting_period=posting,
            amount=Decimal("20.00"),
            expected_preview_fingerprint=preview.fingerprint,
            request_id="goal-reserve-stale",
            reason="Changed amount",
        )
