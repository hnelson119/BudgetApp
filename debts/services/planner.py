from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from zoneinfo import ZoneInfo

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from audit.services import append_event
from budgets.services.calculations import money
from budgets.services.summary import PeriodBudgetSummary, build_period_summary
from debts.models import DebtAccount, DebtPayoffAllocation, DebtPayoffPlan
from debts.services.accounts import current_debt_terms
from debts.services.projections import (
    PayoffProjection,
    PayoffStrategy,
    project_debt_payoff,
    projection_debts_from_accounts,
)
from debts.services.promotions import effective_apr
from households.models import Household
from households.services.access import require_household_membership
from identity.models import User
from periods.models import PayPeriod
from schedules.models import Occurrence, RecurringSource
from schedules.recurrence import BusinessDayAdjustment, Frequency, RecurrenceRule
from schedules.services import (
    RevisionSpec,
    create_recurring_source,
    preview_revision,
    synchronize_occurrences,
)

ZERO = Decimal("0.00")


def _today(household: Household) -> date:
    return timezone.localdate(timezone=ZoneInfo(household.time_zone))


def latest_payoff_plan(household: Household) -> DebtPayoffPlan | None:
    return DebtPayoffPlan.objects.filter(household=household).order_by("-revision_number").first()


def _debts(household: Household) -> tuple[DebtAccount, ...]:
    return tuple(
        DebtAccount.objects.filter(
            household=household, status=DebtAccount.Status.ACTIVE, current_balance__gt=0
        )
        .prefetch_related("terms_revisions")
        .order_by("id")
    )


def payoff_target(
    household: Household, strategy: str, *, on_date: date | None = None
) -> DebtAccount | None:
    debts = _debts(household)
    if not debts:
        return None
    target_date = on_date or _today(household)

    def key(debt: DebtAccount) -> tuple[Decimal | int, Decimal, str]:
        terms = current_debt_terms(debt, on_date=target_date)
        if strategy == DebtPayoffPlan.Strategy.SNOWBALL:
            return debt.current_balance, ZERO, debt.name.casefold()
        if strategy == DebtPayoffPlan.Strategy.CUSTOM:
            return terms.custom_priority, ZERO, debt.name.casefold()
        return -effective_apr(debt, on_date=target_date), debt.current_balance, debt.name.casefold()

    return min(debts, key=key)


def _fingerprint(payload: dict[str, object]) -> str:
    return (
        "sha256$"
        + hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode()
        ).hexdigest()
    )


def planner_snapshot(household: Household) -> tuple[str, Decimal]:
    today = _today(household)
    debts = projection_debts_from_accounts(_debts(household))
    periods = tuple(
        PayPeriod.objects.filter(household=household, next_start_date__gt=today).order_by(
            "start_date"
        )[:8]
    )
    average_days = Decimal(
        sum((item.next_start_date - item.start_date).days for item in periods)
    ) / max(len(periods), 1)
    return _fingerprint(
        {
            "format": "debt-payoff-preview-v2",
            "debts": repr(debts),
            "periods": [
                (item.pk, item.start_date, item.next_start_date, item.status) for item in periods
            ],
        }
    ), average_days


@dataclass(frozen=True, slots=True)
class PlanPreview:
    projection: PayoffProjection
    fingerprint: str
    snapshot_fingerprint: str
    monthly_extra: Decimal
    average_days: Decimal


def preview_payoff_plan(
    *, household: Household, strategy: str, extra_per_period: Decimal, cash_cushion: Decimal
) -> PlanPreview:
    if strategy not in DebtPayoffPlan.Strategy.values:
        raise ValidationError("Select a supported payoff strategy.")
    for amount in (extra_per_period, cash_cushion):
        if (
            not isinstance(amount, Decimal)
            or not amount.is_finite()
            or amount < 0
            or amount != money(amount)
        ):
            raise ValidationError("Plan amounts must be nonnegative dollars and cents.")
    snapshot, average_days = planner_snapshot(household)
    if average_days <= 0:
        raise ValidationError(
            "Create an income schedule and paycheck periods before saving a payoff plan."
        )
    debts = projection_debts_from_accounts(_debts(household))
    if not debts:
        raise ValidationError("Add an active debt with a balance before saving a payoff plan.")
    monthly_extra = money(extra_per_period * Decimal(365) / (average_days * 12))
    projection = project_debt_payoff(
        debts,
        strategy=PayoffStrategy(strategy),
        monthly_extra=monthly_extra,
        start_date=_today(household),
        max_months=480,
    )
    current = latest_payoff_plan(household)
    fingerprint = _fingerprint(
        {
            "snapshot": snapshot,
            "as_of": _today(household),
            "strategy": strategy,
            "extra": extra_per_period,
            "cushion": cash_cushion,
            "current_plan": current.pk if current else None,
        }
    )
    return PlanPreview(projection, fingerprint, snapshot, monthly_extra, average_days)


@transaction.atomic
def save_payoff_plan(
    *,
    household: Household,
    actor: User,
    strategy: str,
    extra_per_period: Decimal,
    cash_cushion: Decimal,
    expected_fingerprint: str,
    request_id: str,
) -> DebtPayoffPlan:
    require_household_membership(actor, household)
    Household.objects.select_for_update().get(pk=household.pk)
    preview = preview_payoff_plan(
        household=household,
        strategy=strategy,
        extra_per_period=extra_per_period,
        cash_cushion=cash_cushion,
    )
    if preview.fingerprint != expected_fingerprint:
        raise ValidationError(
            "Your debts, paycheck periods, or plan changed. Preview the plan again."
        )
    previous = latest_payoff_plan(household)
    plan = DebtPayoffPlan(
        household=household,
        revision_number=previous.revision_number + 1 if previous else 1,
        strategy=strategy,
        extra_per_period=extra_per_period,
        cash_cushion=cash_cushion,
        snapshot_fingerprint=preview.snapshot_fingerprint,
        created_by=actor,
        forecast={
            "as_of": _today(household).isoformat(),
            "payoff_date": preview.projection.payoff_date.isoformat()
            if preview.projection.payoff_date
            else None,
            "total_interest": str(preview.projection.total_interest),
            "monthly_extra": str(preview.monthly_extra),
            "average_days": str(preview.average_days),
            "baseline_payments": {
                debt.identifier: str(terms.minimum_payment + terms.recurring_extra_payment)
                for debt in projection_debts_from_accounts(_debts(household))
                for terms in (
                    tuple(item for item in debt.terms if item.effective_from <= _today(household))[
                        -1
                    ],
                )
            },
        },
    )
    plan.full_clean()
    plan._service_authorized = True  # type: ignore[attr-defined]
    plan.save()
    append_event(
        household=household,
        actor=actor,
        action="debt.payoff_plan_saved",
        entity_type="debt_payoff_plan",
        entity_id=plan.pk,
        request_id=request_id,
        before={"plan_id": previous.pk if previous else None},
        after={
            "strategy": strategy,
            "extra_per_period": extra_per_period,
            "cash_cushion": cash_cushion,
            "revision_number": plan.revision_number,
        },
    )
    return plan


@dataclass(frozen=True, slots=True)
class PaymentPreview:
    plan: DebtPayoffPlan
    period: PayPeriod
    debt: DebtAccount
    amount: Decimal
    available: Decimal
    summary: PeriodBudgetSummary
    fingerprint: str
    rollover_extra: Decimal


def rollover_extra(plan: DebtPayoffPlan) -> Decimal:
    baseline = plan.forecast.get("baseline_payments", {})
    paid_ids = {
        str(item.pk)
        for item in DebtAccount.objects.filter(
            household=plan.household, pk__in=baseline, current_balance=0
        )
    }
    freed_monthly = sum(
        (Decimal(amount) for identifier, amount in baseline.items() if identifier in paid_ids), ZERO
    )
    _, average_days = planner_snapshot(plan.household)
    return money(freed_monthly * average_days * 12 / Decimal(365))


def _available(summary: PeriodBudgetSummary) -> Decimal:
    overruns = sum(
        (
            max(actual - planned, ZERO)
            for actual, planned in (
                (summary.actual_fixed_expenses, summary.planned_fixed_expenses),
                (summary.actual_debt_payments, summary.planned_debt_payments),
                (summary.actual_goal_contributions, summary.planned_goal_contributions),
                (summary.actual_variable_spending, summary.variable_spending_budget),
            )
        ),
        ZERO,
    )
    income = Occurrence.objects.filter(
        pay_period=summary.period,
        source__kind=RecurringSource.Kind.INCOME,
        status__in=(Occurrence.Status.COMPLETED, Occurrence.Status.CORRECTED),
    )
    shortfall = sum(
        (max(item.planned_amount - (item.actual_amount or ZERO), ZERO) for item in income), ZERO
    )
    return money(summary.unallocated_excess - overruns - shortfall)


def preview_payoff_payment(*, household: Household, period: PayPeriod) -> PaymentPreview:
    if period.household_id != household.pk:
        raise ValidationError("The paycheck period belongs to another household.")
    today = _today(household)
    if (
        period.status
        not in (PayPeriod.Status.PROJECTED, PayPeriod.Status.OPEN, PayPeriod.Status.REOPENED)
        or period.display_end_date < today
    ):
        raise ValidationError("Select a current or future editable paycheck period.")
    if DebtPayoffAllocation.objects.filter(pay_period=period).exists():
        raise ValidationError(
            "An extra payment was already planned for this period. Edit or cancel it in Budget."
        )
    plan = latest_payoff_plan(household)
    if plan is None:
        raise ValidationError("Save a payoff plan before adding extra payments to Budget.")
    target = payoff_target(household, plan.strategy, on_date=max(today, period.start_date))
    if target is None:
        raise ValidationError("No active debt balance remains to target.")
    summary = build_period_summary(household=household, period=period, today=today)
    available = _available(summary)
    # Keep enough forecast cash for deficits in the following three paycheck periods.
    running = available
    future_summaries = []
    for following in PayPeriod.objects.filter(
        household=household, start_date__gte=period.next_start_date
    ).order_by("start_date")[:3]:
        following_summary = build_period_summary(household=household, period=following, today=today)
        future_summaries.append(repr(following_summary))
        running += _available(following_summary)
        available = min(available, running)
    available = money(max(available - plan.cash_cushion, ZERO))
    reserved = sum(
        (
            item.planned_amount
            for item in Occurrence.objects.filter(
                pay_period__household=household,
                expected_date__lte=period.display_end_date,
                source_revision__configuration__debt_account_id=str(target.pk),
            ).exclude(status__in=(Occurrence.Status.CANCELLED, Occurrence.Status.SUPERSEDED))
        ),
        ZERO,
    )
    rolled = rollover_extra(plan)
    amount = money(
        min(plan.extra_per_period + rolled, available, max(target.current_balance - reserved, ZERO))
    )
    snapshot, _ = planner_snapshot(household)
    fingerprint = _fingerprint(
        {
            "snapshot": snapshot,
            "plan": plan.pk,
            "as_of": today,
            "available": available,
            "period": (period.pk, period.start_date, period.next_start_date, period.status),
            "summary": repr(summary),
            "future": future_summaries,
            "target": target.pk,
            "reserved": reserved,
            "amount": amount,
        }
    )
    return PaymentPreview(plan, period, target, amount, available, summary, fingerprint, rolled)


@transaction.atomic
def apply_payoff_payment(
    *,
    household: Household,
    period: PayPeriod,
    actor: User,
    expected_fingerprint: str,
    request_id: str,
) -> DebtPayoffAllocation:
    require_household_membership(actor, household)
    Household.objects.select_for_update().get(pk=household.pk)
    locked = PayPeriod.objects.select_for_update().get(pk=period.pk)
    preview = preview_payoff_payment(household=household, period=locked)
    if preview.fingerprint != expected_fingerprint:
        raise ValidationError("Your budget or debts changed. Preview the extra payment again.")
    if preview.amount <= 0:
        raise ValidationError("No extra payment fits this period's budget and cash cushion.")
    payment_date = max(_today(household), locked.start_date)
    spec = RevisionSpec(
        effective_from=payment_date,
        expected_amount=preview.amount,
        rule=RecurrenceRule(Frequency.ONCE, payment_date),
        adjustment_policy=BusinessDayAdjustment.NONE,
        configuration={
            "cash_flow_component": "strategy_extra_payment",
            "debt_account_id": str(preview.debt.pk),
            "payoff_plan_id": str(preview.plan.pk),
        },
    )
    source, _ = create_recurring_source(
        household=household,
        actor=actor,
        kind=RecurringSource.Kind.DEBT_PAYMENT,
        name=f"{preview.debt.name[:75]} · extra {locked.start_date.isoformat()}",
        revision_spec=spec,
        expected_preview_fingerprint=preview_revision(spec, preview_from=payment_date).fingerprint,
        request_id=request_id,
    )
    synchronize_occurrences(
        household=household,
        actor=actor,
        window_start=locked.start_date,
        window_end=locked.display_end_date,
        source_ids=(source.pk,),
        request_id=request_id,
    )
    occurrence = source.occurrences.get(pay_period=locked, status=Occurrence.Status.SCHEDULED)
    allocation = DebtPayoffAllocation(
        plan=preview.plan,
        pay_period=locked,
        debt=preview.debt,
        occurrence=occurrence,
        amount=preview.amount,
        created_by=actor,
    )
    allocation.full_clean()
    allocation._service_authorized = True  # type: ignore[attr-defined]
    allocation.save()
    append_event(
        household=household,
        actor=actor,
        action="debt.payoff_extra_allocated",
        entity_type="debt_payoff_allocation",
        entity_id=allocation.pk,
        request_id=request_id,
        after={
            "plan_id": preview.plan.pk,
            "period_id": locked.pk,
            "debt_id": preview.debt.pk,
            "occurrence_id": occurrence.pk,
            "amount": preview.amount,
        },
    )
    return allocation
