from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time
from decimal import Decimal
from uuid import UUID
from zoneinfo import ZoneInfo

from django.db.models import QuerySet

from budgets.models import OccurrenceReconciliation, VariableBudget
from budgets.services.calculations import PeriodActuals, PeriodPlan, money, spending_remaining
from households.models import Household
from ledger.models import JournalEntry
from periods.models import PayPeriod
from reserves.services import reserve_balance
from schedules.models import Occurrence, RecurringSource

ZERO = Decimal("0.00")


@dataclass(frozen=True, slots=True)
class CategoryBudgetSummary:
    budget: VariableBudget
    actual: Decimal
    remaining: Decimal


@dataclass(frozen=True, slots=True)
class RecentTransaction:
    entry: JournalEntry
    amount: Decimal


@dataclass(frozen=True, slots=True)
class PeriodBudgetSummary:
    period: PayPeriod
    planned_income: Decimal
    actual_income: Decimal
    planned_fixed_expenses: Decimal
    actual_fixed_expenses: Decimal
    planned_debt_payments: Decimal
    actual_debt_payments: Decimal
    planned_goal_contributions: Decimal
    actual_goal_contributions: Decimal
    variable_spending_budget: Decimal
    actual_variable_spending: Decimal
    allocatable_amount: Decimal
    unallocated_excess: Decimal
    spending_remaining: Decimal
    projected_closing_surplus: Decimal
    household_reserve: Decimal
    status: str
    status_label: str
    upcoming_bills: tuple[Occurrence, ...]
    goal_items: tuple[Occurrence, ...]
    recent_transactions: tuple[RecentTransaction, ...]
    category_budgets: tuple[CategoryBudgetSummary, ...]

    @property
    def planned_required(self) -> Decimal:
        return money(self.planned_fixed_expenses + self.planned_debt_payments)

    @property
    def variable_progress_max(self) -> Decimal:
        return max(self.variable_spending_budget, Decimal("1.00"))

    @property
    def variable_progress_value(self) -> Decimal:
        return max(self.actual_variable_spending, ZERO)


def period_occurrences(
    period: PayPeriod,
    *,
    include_cancelled: bool = False,
) -> QuerySet[Occurrence]:
    occurrences = Occurrence.objects.filter(pay_period=period).exclude(
        status=Occurrence.Status.SUPERSEDED
    )
    if not include_cancelled:
        occurrences = occurrences.exclude(status=Occurrence.Status.CANCELLED)
    return occurrences.select_related(
        "source",
        "source_revision",
        "source__expense_detail",
        "source__expense_detail__category",
    ).order_by("source__kind", "expected_date", "source__name")


def _occurrence_sum(occurrences: list[Occurrence], kind: str, field: str) -> Decimal:
    return money(
        sum(
            (
                getattr(item, field)
                for item in occurrences
                if item.source.kind == kind and getattr(item, field) is not None
            ),
            ZERO,
        )
    )


def _entry_amount(entry: JournalEntry) -> Decimal:
    total = sum(
        (posting.amount for posting in entry.postings.all() if posting.side == "debit"),
        ZERO,
    )
    return money(-total if entry.reversal_of_id else total)


def _period_entries(household: Household, period: PayPeriod) -> list[JournalEntry]:
    household_zone = ZoneInfo(household.time_zone)
    starts_at = datetime.combine(period.start_date, time.min, tzinfo=household_zone)
    ends_at = datetime.combine(period.next_start_date, time.min, tzinfo=household_zone)
    return list(
        JournalEntry.objects.filter(
            household=household,
            effective_at__gte=starts_at,
            effective_at__lt=ends_at,
        )
        .select_related("category")
        .prefetch_related("postings")
        .order_by("-effective_at", "-created_at")
    )


def _unlinked_entry_total(
    entries: list[JournalEntry],
    linked_entry_ids: set[UUID],
    entry_type: str,
) -> Decimal:
    return money(
        sum(
            (
                _entry_amount(entry)
                for entry in entries
                if entry.entry_type == entry_type and entry.pk not in linked_entry_ids
            ),
            ZERO,
        )
    )


def _status(
    *,
    has_plan: bool,
    unallocated: Decimal,
    spending_left: Decimal,
    overdue: bool,
    actual_variance_needs_attention: bool,
) -> tuple[str, str]:
    if not has_plan:
        return "awaiting", "Awaiting budget"
    if unallocated < 0:
        return "deficit", "Deficit"
    if spending_left < 0 or overdue or actual_variance_needs_attention:
        return "attention", "Attention needed"
    return "on_track", "On track"


def build_period_summary(
    *,
    household: Household,
    period: PayPeriod,
    today: date,
) -> PeriodBudgetSummary:
    if period.household_id != household.pk:
        raise ValueError("The paycheck period belongs to another household.")
    occurrences = list(period_occurrences(period))
    entries = _period_entries(household, period)
    reconciliations = list(
        OccurrenceReconciliation.objects.filter(
            household=household,
            occurrence__pay_period=period,
        ).select_related("occurrence__source")
    )
    linked_entry_ids = {item.journal_entry_id for item in reconciliations}
    fixed_entry_ids = {
        item.journal_entry_id
        for item in reconciliations
        if item.occurrence.source.kind == RecurringSource.Kind.FIXED_EXPENSE
    }

    planned_income = _occurrence_sum(occurrences, RecurringSource.Kind.INCOME, "planned_amount")
    planned_fixed = _occurrence_sum(
        occurrences, RecurringSource.Kind.FIXED_EXPENSE, "planned_amount"
    )
    planned_debt = _occurrence_sum(occurrences, RecurringSource.Kind.DEBT_PAYMENT, "planned_amount")
    planned_goals = _occurrence_sum(
        occurrences, RecurringSource.Kind.GOAL_CONTRIBUTION, "planned_amount"
    )
    actual_income = money(
        _occurrence_sum(occurrences, RecurringSource.Kind.INCOME, "actual_amount")
        + _unlinked_entry_total(entries, linked_entry_ids, JournalEntry.EntryType.INCOME)
    )
    actual_fixed = _occurrence_sum(occurrences, RecurringSource.Kind.FIXED_EXPENSE, "actual_amount")
    actual_debt = money(
        _occurrence_sum(occurrences, RecurringSource.Kind.DEBT_PAYMENT, "actual_amount")
        + _unlinked_entry_total(entries, linked_entry_ids, JournalEntry.EntryType.DEBT_PAYMENT)
    )
    actual_goals = money(
        _occurrence_sum(occurrences, RecurringSource.Kind.GOAL_CONTRIBUTION, "actual_amount")
        + _unlinked_entry_total(entries, linked_entry_ids, JournalEntry.EntryType.GOAL_CONTRIBUTION)
    )
    variable_entries = [
        entry
        for entry in entries
        if entry.entry_type == JournalEntry.EntryType.EXPENSE and entry.pk not in fixed_entry_ids
    ]
    actual_variable = money(sum((_entry_amount(entry) for entry in variable_entries), ZERO))

    variable_budgets = list(
        VariableBudget.objects.filter(pay_period=period)
        .select_related("category")
        .order_by("category__sort_order", "category__name")
    )
    variable_total = money(sum((item.planned_amount for item in variable_budgets), ZERO))
    actual_by_category: dict[UUID, Decimal] = {}
    for entry in variable_entries:
        if entry.category_id is not None:
            actual_by_category[entry.category_id] = money(
                actual_by_category.get(entry.category_id, ZERO) + _entry_amount(entry)
            )
    category_summaries = tuple(
        CategoryBudgetSummary(
            budget=item,
            actual=actual_by_category.get(item.category_id, ZERO),
            remaining=money(item.planned_amount - actual_by_category.get(item.category_id, ZERO)),
        )
        for item in variable_budgets
    )

    plan = PeriodPlan(
        planned_income=planned_income,
        planned_fixed_expenses=planned_fixed,
        current_income_funded_required_debt=planned_debt,
        scheduled_goal_contributions=planned_goals,
        safety_buffer=ZERO,
        variable_spending_budget=variable_total,
    )
    actuals = PeriodActuals(
        actual_income_received=actual_income,
        actual_fixed_expenses=actual_fixed,
        current_income_funded_debt_payments=actual_debt,
        actual_goal_contributions=actual_goals,
        actual_variable_spending=actual_variable,
    )
    # A one-off receipt is immediately visible without rewriting the recurring income plan.
    positive_income_variance = max(actual_income - planned_income, ZERO)
    current_unallocated = money(plan.unallocated_excess() + positive_income_variance)
    spending_left = spending_remaining(variable_total, actual_variable)
    upcoming = tuple(
        item
        for item in occurrences
        if item.source.kind
        in (
            RecurringSource.Kind.FIXED_EXPENSE,
            RecurringSource.Kind.DEBT_PAYMENT,
        )
        and item.status not in (Occurrence.Status.COMPLETED, Occurrence.Status.CORRECTED)
    )[:6]
    goal_items = tuple(
        item for item in occurrences if item.source.kind == RecurringSource.Kind.GOAL_CONTRIBUTION
    )
    overdue = any(item.expected_date < today for item in upcoming)
    completed_income_plan = money(
        sum(
            (
                item.planned_amount
                for item in occurrences
                if item.source.kind == RecurringSource.Kind.INCOME
                and item.status in (Occurrence.Status.COMPLETED, Occurrence.Status.CORRECTED)
            ),
            ZERO,
        )
    )
    actual_occurrence_income = _occurrence_sum(
        occurrences,
        RecurringSource.Kind.INCOME,
        "actual_amount",
    )
    actual_variance_needs_attention = (
        actual_occurrence_income < completed_income_plan
        or actual_fixed > planned_fixed
        or actual_debt > planned_debt
        or actual_goals > planned_goals
    )
    has_plan = any(
        value != ZERO
        for value in (planned_income, planned_fixed, planned_debt, planned_goals, variable_total)
    )
    status, status_label = _status(
        has_plan=has_plan,
        unallocated=current_unallocated,
        spending_left=spending_left,
        overdue=overdue,
        actual_variance_needs_attention=actual_variance_needs_attention,
    )
    recent = tuple(
        RecentTransaction(entry=entry, amount=_entry_amount(entry)) for entry in entries[:6]
    )
    return PeriodBudgetSummary(
        period=period,
        planned_income=planned_income,
        actual_income=actual_income,
        planned_fixed_expenses=planned_fixed,
        actual_fixed_expenses=actual_fixed,
        planned_debt_payments=planned_debt,
        actual_debt_payments=actual_debt,
        planned_goal_contributions=planned_goals,
        actual_goal_contributions=actual_goals,
        variable_spending_budget=variable_total,
        actual_variable_spending=actual_variable,
        allocatable_amount=plan.allocatable_amount(),
        unallocated_excess=current_unallocated,
        spending_remaining=spending_left,
        projected_closing_surplus=actuals.closing_surplus(),
        household_reserve=reserve_balance(household),
        status=status,
        status_label=status_label,
        upcoming_bills=upcoming,
        goal_items=goal_items,
        recent_transactions=recent,
        category_budgets=category_summaries,
    )
