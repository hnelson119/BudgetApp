from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date, datetime
from decimal import ROUND_CEILING, Decimal, InvalidOperation
from zoneinfo import ZoneInfo

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Sum
from django.utils import timezone

from audit.services import append_event
from budgets.services.reconciliation import reconcile_occurrence
from debts.models import DebtAccount
from goals.models import Goal, GoalContribution, GoalFundingPlan, GoalRevision
from households.models import Household
from households.services.access import require_household_membership
from identity.models import User
from ledger.models import FinancialAccount
from ledger.services.entries import (
    record_debt_payment,
)
from ledger.services.entries import (
    record_goal_contribution as record_ledger_goal_contribution,
)
from periods.models import PayPeriod
from reserves.models import ReserveEntry
from reserves.services import allocate_reserve, reserve_balance
from schedules.models import Occurrence, RecurringSource
from schedules.recurrence import BusinessDayAdjustment, Frequency, RecurrenceRule
from schedules.services.sources import (
    RevisionSpec,
    create_recurring_source,
    preview_revision,
    revise_recurring_source,
)
from schedules.services.sync import synchronize_occurrences

_CENT = Decimal("0.01")


@dataclass(frozen=True, slots=True)
class GoalSpec:
    effective_from: date
    name: str
    goal_type: str
    target_amount: Decimal
    target_date: date | None
    contribution_per_period: Decimal
    priority: int
    status: str
    automatic_excess_allocation: bool
    source_account: FinancialAccount
    destination_account: FinancialAccount | None = None
    linked_debt: DebtAccount | None = None
    notes: str = ""


@dataclass(frozen=True, slots=True)
class GoalPreview:
    next_period_starts: tuple[date, ...]
    fingerprint: str


@dataclass(frozen=True, slots=True)
class GoalProgress:
    goal: Goal
    revision: GoalRevision
    current_amount: Decimal
    remaining_amount: Decimal
    progress_percent: Decimal
    projected_completion_date: date | None


@dataclass(frozen=True, slots=True)
class ReserveAllocationPreview:
    goal: Goal
    amount: Decimal
    reserve_before: Decimal
    reserve_after: Decimal
    goal_before: Decimal
    goal_after: Decimal
    fingerprint: str


@dataclass(frozen=True, slots=True)
class PriorityAllocationItem:
    goal: Goal
    revision: GoalRevision
    amount: Decimal


@dataclass(frozen=True, slots=True)
class PriorityAllocationPreview:
    allocations: tuple[PriorityAllocationItem, ...]
    reserve_before: Decimal
    reserve_after: Decimal
    fingerprint: str


def _money(value: Decimal, *, label: str, positive: bool = False) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ValidationError(f"{label} must use a finite Decimal value.")
    try:
        normalized = value.quantize(_CENT)
    except InvalidOperation as error:
        raise ValidationError(f"{label} is invalid.") from error
    if normalized != value or normalized < 0 or (positive and normalized == 0):
        qualifier = "positive" if positive else "nonnegative"
        raise ValidationError(f"{label} must be {qualifier} with at most two decimals.")
    return normalized


def _validate_account(account: FinancialAccount, household: Household, *, label: str) -> None:
    if account.household_id != household.pk:
        raise ValidationError(f"The {label} account belongs to another household.")
    if account.is_archived or account.classification != FinancialAccount.Classification.ASSET:
        raise ValidationError(f"The {label} account must be an active asset account.")


def _validate_spec(
    household: Household,
    spec: GoalSpec,
    *,
    opening_amount: Decimal | None = None,
) -> tuple[Decimal, Decimal]:
    name = spec.name.strip()
    if not name:
        raise ValidationError("Goal name is required.")
    if len(name) > 120 or len(spec.notes.strip()) > 500:
        raise ValidationError("Goal text exceeds the allowed length.")
    if spec.goal_type not in GoalRevision.GoalType.values:
        raise ValidationError("Goal type is invalid.")
    if spec.status not in GoalRevision.Status.values:
        raise ValidationError("Goal status is invalid.")
    if not isinstance(spec.priority, int) or isinstance(spec.priority, bool) or spec.priority < 1:
        raise ValidationError("Goal priority must be a positive whole number.")
    target = _money(spec.target_amount, label="Target amount", positive=True)
    contribution = _money(spec.contribution_per_period, label="Contribution per paycheck")
    if spec.target_date is not None and spec.target_date < spec.effective_from:
        raise ValidationError("The target date cannot precede the effective date.")
    if opening_amount is not None:
        opening = _money(opening_amount, label="Opening amount")
        if opening > target:
            raise ValidationError("Opening progress cannot exceed the goal target.")
    _validate_account(spec.source_account, household, label="source")
    if spec.goal_type == GoalRevision.GoalType.DEBT_PAYOFF:
        if spec.destination_account is not None or spec.linked_debt is None:
            raise ValidationError(
                "Debt-payoff goals require a linked debt, not a destination account."
            )
        debt = spec.linked_debt
        if debt.household_id != household.pk or not debt.is_active:
            raise ValidationError("The linked debt must be active in this household.")
        if (
            debt.financial_account is None
            or debt.financial_account.is_archived
            or debt.financial_account.classification != FinancialAccount.Classification.LIABILITY
        ):
            raise ValidationError("The linked debt needs an active liability financial account.")
    else:
        if spec.linked_debt is not None or spec.destination_account is None:
            raise ValidationError("Savings and investing goals require a destination account.")
        _validate_account(spec.destination_account, household, label="destination")
        if spec.destination_account.pk == spec.source_account.pk:
            raise ValidationError("Goal source and destination accounts must differ.")
    return target, contribution


def _fingerprint(payload: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def preview_goal(
    *,
    household: Household,
    spec: GoalSpec,
    opening_amount: Decimal | None = None,
) -> GoalPreview:
    target, contribution = _validate_spec(household, spec, opening_amount=opening_amount)
    period_starts: tuple[date, ...] = ()
    if contribution > 0 and spec.status == GoalRevision.Status.ACTIVE:
        period_starts = tuple(
            PayPeriod.objects.filter(
                household=household,
                start_date__gte=spec.effective_from,
            )
            .order_by("start_date")
            .values_list("start_date", flat=True)[:3]
        )
        if not period_starts:
            raise ValidationError("Generate paycheck periods before scheduling goal funding.")
    payload: dict[str, object] = {
        "effective_from": spec.effective_from.isoformat(),
        "name": spec.name.strip(),
        "goal_type": spec.goal_type,
        "target_amount": format(target, "f"),
        "target_date": spec.target_date.isoformat() if spec.target_date else None,
        "contribution_per_period": format(contribution, "f"),
        "priority": spec.priority,
        "status": spec.status,
        "automatic_excess_allocation": spec.automatic_excess_allocation,
        "source_account_id": str(spec.source_account.pk),
        "destination_account_id": (
            str(spec.destination_account.pk) if spec.destination_account else None
        ),
        "linked_debt_id": str(spec.linked_debt.pk) if spec.linked_debt else None,
        "notes": spec.notes.strip(),
        "opening_amount": format(opening_amount, "f") if opening_amount is not None else None,
        "next_period_starts": [value.isoformat() for value in period_starts],
    }
    return GoalPreview(period_starts, _fingerprint(payload))


def _save_record(record: Goal | GoalRevision | GoalFundingPlan | GoalContribution) -> None:
    record.full_clean()
    record.__dict__["_service_authorized"] = True
    record.save()


def _create_revision(
    *,
    goal: Goal,
    actor: User,
    revision_number: int,
    spec: GoalSpec,
) -> GoalRevision:
    revision = GoalRevision(
        goal=goal,
        revision_number=revision_number,
        effective_from=spec.effective_from,
        name=spec.name.strip(),
        goal_type=spec.goal_type,
        target_amount=spec.target_amount,
        target_date=spec.target_date,
        contribution_per_period=spec.contribution_per_period,
        priority=spec.priority,
        status=spec.status,
        automatic_excess_allocation=spec.automatic_excess_allocation,
        source_account=spec.source_account,
        destination_account=spec.destination_account,
        linked_debt=spec.linked_debt,
        notes=spec.notes.strip(),
        created_by=actor,
    )
    _save_record(revision)
    return revision


def _schedule_spec(goal: Goal, spec: GoalSpec) -> RevisionSpec:
    active = spec.status == GoalRevision.Status.ACTIVE and spec.contribution_per_period > Decimal(
        "0.00"
    )
    return RevisionSpec(
        effective_from=spec.effective_from,
        expected_amount=spec.contribution_per_period,
        rule=RecurrenceRule(frequency=Frequency.ONCE, start_date=spec.effective_from),
        adjustment_policy=BusinessDayAdjustment.NONE,
        configuration={
            "cadence": "pay_period_start",
            "goal_id": str(goal.pk),
            "goal_status": "active" if active else "paused",
        },
    )


def _synchronize_available_periods(
    *,
    household: Household,
    actor: User,
    request_id: str,
) -> None:
    first = PayPeriod.objects.filter(household=household).order_by("start_date").first()
    last = PayPeriod.objects.filter(household=household).order_by("-next_start_date").first()
    if first is not None and last is not None:
        synchronize_occurrences(
            household=household,
            actor=actor,
            window_start=first.start_date,
            window_end=last.display_end_date,
            request_id=request_id,
        )


def _create_or_revise_funding_plan(
    *,
    goal: Goal,
    actor: User,
    spec: GoalSpec,
    request_id: str,
    reason: str,
) -> GoalFundingPlan | None:
    plan = GoalFundingPlan.objects.filter(goal=goal).select_related("source").first()
    if plan is None and spec.contribution_per_period == Decimal("0.00"):
        return None
    schedule_spec = _schedule_spec(goal, spec)
    schedule_preview = preview_revision(schedule_spec, preview_from=spec.effective_from)
    if plan is None:
        source, _ = create_recurring_source(
            household=goal.household,
            actor=actor,
            kind=RecurringSource.Kind.GOAL_CONTRIBUTION,
            name=f"Goal {goal.pk.hex[:8]} · {spec.name.strip()}",
            revision_spec=schedule_spec,
            expected_preview_fingerprint=schedule_preview.fingerprint,
            request_id=request_id,
            notes="Paycheck-period goal funding; maintained by Goals.",
        )
        plan = GoalFundingPlan(goal=goal, source=source, created_by=actor)
        _save_record(plan)
    else:
        revise_recurring_source(
            source=plan.source,
            actor=actor,
            revision_spec=schedule_spec,
            expected_preview_fingerprint=schedule_preview.fingerprint,
            request_id=request_id,
            reason=reason,
        )
    _synchronize_available_periods(
        household=goal.household,
        actor=actor,
        request_id=request_id,
    )
    return plan


@transaction.atomic
def create_goal(
    *,
    household: Household,
    actor: User,
    spec: GoalSpec,
    opening_amount: Decimal,
    expected_preview_fingerprint: str,
    request_id: str,
) -> tuple[Goal, GoalRevision]:
    require_household_membership(actor, household)
    preview = preview_goal(household=household, spec=spec, opening_amount=opening_amount)
    if preview.fingerprint != expected_preview_fingerprint:
        raise ValidationError("The goal preview is stale; preview it again before saving.")
    if GoalRevision.objects.filter(
        goal__household=household,
        name__iexact=spec.name.strip(),
    ).exists():
        raise ValidationError("A goal with this name already exists in the household.")
    goal = Goal(
        household=household,
        opening_amount=_money(opening_amount, label="Opening amount"),
        created_by=actor,
    )
    _save_record(goal)
    revision = _create_revision(goal=goal, actor=actor, revision_number=1, spec=spec)
    _create_or_revise_funding_plan(
        goal=goal,
        actor=actor,
        spec=spec,
        request_id=request_id,
        reason="Initial goal funding plan",
    )
    append_event(
        household=household,
        actor=actor,
        action="goal.created",
        entity_type="goal",
        entity_id=goal.pk,
        request_id=request_id,
        after={
            "revision_id": revision.pk,
            "name": revision.name,
            "goal_type": revision.goal_type,
            "opening_amount": goal.opening_amount,
            "target_amount": revision.target_amount,
            "contribution_per_period": revision.contribution_per_period,
            "priority": revision.priority,
            "automatic_excess_allocation": revision.automatic_excess_allocation,
        },
    )
    return goal, revision


@transaction.atomic
def revise_goal(
    *,
    goal: Goal,
    actor: User,
    spec: GoalSpec,
    expected_preview_fingerprint: str,
    request_id: str,
    reason: str,
) -> GoalRevision:
    locked = Goal.objects.select_for_update().select_related("household").get(pk=goal.pk)
    require_household_membership(actor, locked.household)
    reason = reason.strip()
    if not reason:
        raise ValidationError("Goal revisions require a reason.")
    preview = preview_goal(household=locked.household, spec=spec)
    if preview.fingerprint != expected_preview_fingerprint:
        raise ValidationError("The goal preview is stale; preview it again before saving.")
    latest = locked.revisions.order_by("-revision_number").first()
    if latest is None:
        raise ValidationError("The goal has no initial revision.")
    if spec.effective_from <= latest.effective_from:
        raise ValidationError("A goal revision must take effect after the latest revision.")
    duplicate = GoalRevision.objects.filter(
        goal__household=locked.household,
        name__iexact=spec.name.strip(),
    ).exclude(goal=locked)
    if duplicate.exists():
        raise ValidationError("A goal with this name already exists in the household.")
    revision = _create_revision(
        goal=locked,
        actor=actor,
        revision_number=latest.revision_number + 1,
        spec=spec,
    )
    _create_or_revise_funding_plan(
        goal=locked,
        actor=actor,
        spec=spec,
        request_id=request_id,
        reason=reason,
    )
    append_event(
        household=locked.household,
        actor=actor,
        action="goal.revised",
        entity_type="goal_revision",
        entity_id=revision.pk,
        request_id=request_id,
        before={
            "revision_id": latest.pk,
            "name": latest.name,
            "target_amount": latest.target_amount,
            "contribution_per_period": latest.contribution_per_period,
            "priority": latest.priority,
            "status": latest.status,
            "automatic_excess_allocation": latest.automatic_excess_allocation,
        },
        after={
            "revision_number": revision.revision_number,
            "effective_from": revision.effective_from,
            "name": revision.name,
            "target_amount": revision.target_amount,
            "contribution_per_period": revision.contribution_per_period,
            "priority": revision.priority,
            "status": revision.status,
            "automatic_excess_allocation": revision.automatic_excess_allocation,
        },
        reason=reason,
    )
    return revision


def current_goal_revision(goal: Goal, *, on_date: date) -> GoalRevision:
    revision = (
        goal.revisions.filter(effective_from__lte=on_date)
        .order_by("-effective_from", "-revision_number")
        .first()
    )
    if revision is None:
        raise ValidationError("The goal has no revision effective on this date.")
    return revision


def goal_current_amount(goal: Goal) -> Decimal:
    contributed = goal.contributions.aggregate(total=Sum("amount"))["total"] or Decimal("0.00")
    return goal.opening_amount + contributed


def _projected_completion(
    *,
    household: Household,
    revision: GoalRevision,
    remaining: Decimal,
    on_date: date,
) -> date | None:
    if remaining <= 0:
        return on_date
    if revision.status != GoalRevision.Status.ACTIVE or revision.contribution_per_period <= 0:
        return None
    count = int(
        (remaining / revision.contribution_per_period).to_integral_value(rounding=ROUND_CEILING)
    )
    starts = list(
        PayPeriod.objects.filter(household=household, start_date__gte=on_date)
        .order_by("start_date")
        .values_list("start_date", flat=True)[:count]
    )
    return starts[-1] if len(starts) == count else None


def goal_progress_rows(*, household: Household, on_date: date) -> tuple[GoalProgress, ...]:
    rows: list[GoalProgress] = []
    goals = Goal.objects.filter(household=household).prefetch_related("revisions", "contributions")
    for goal in goals:
        try:
            revision = current_goal_revision(goal, on_date=on_date)
        except ValidationError:
            continue
        current = goal_current_amount(goal)
        remaining = max(revision.target_amount - current, Decimal("0.00"))
        percent = min(
            (current / revision.target_amount * Decimal("100.00")).quantize(_CENT),
            Decimal("100.00"),
        )
        rows.append(
            GoalProgress(
                goal=goal,
                revision=revision,
                current_amount=current,
                remaining_amount=remaining,
                progress_percent=percent,
                projected_completion_date=_projected_completion(
                    household=household,
                    revision=revision,
                    remaining=remaining,
                    on_date=on_date,
                ),
            )
        )
    return tuple(
        sorted(rows, key=lambda row: (row.revision.priority, row.revision.name.casefold()))
    )


def _effective_local_date(effective_at: datetime, household: Household) -> date:
    if timezone.is_naive(effective_at):
        raise ValidationError("Goal contribution timestamps must include a time zone.")
    return timezone.localtime(effective_at, ZoneInfo(household.time_zone)).date()


def _contribution_idempotency(goal: Goal, request_id: str) -> str:
    return hashlib.sha256(f"goal:{goal.pk}:{request_id}".encode()).hexdigest()


@transaction.atomic
def record_goal_contribution(
    *,
    goal: Goal,
    actor: User,
    pay_period: PayPeriod,
    amount: Decimal,
    effective_at: datetime,
    request_id: str,
    reason: str,
    contribution_type: str = GoalContribution.ContributionType.MANUAL,
    occurrence: Occurrence | None = None,
    reserve_entry: ReserveEntry | None = None,
) -> GoalContribution:
    locked = Goal.objects.select_for_update().select_related("household").get(pk=goal.pk)
    require_household_membership(actor, locked.household)
    period = PayPeriod.objects.select_for_update().get(pk=pay_period.pk)
    if period.household_id != locked.household_id:
        raise ValidationError("The paycheck period belongs to another household.")
    if period.status == PayPeriod.Status.CLOSED:
        raise ValidationError("Goal contributions cannot post to a closed paycheck period.")
    local_date = _effective_local_date(effective_at, locked.household)
    if not period.contains(local_date):
        raise ValidationError("The contribution date is outside the selected paycheck period.")
    normalized = _money(amount, label="Contribution amount", positive=True)
    revision = current_goal_revision(locked, on_date=local_date)
    if revision.status == GoalRevision.Status.COMPLETED:
        raise ValidationError("Completed goals cannot receive new contributions.")
    if contribution_type not in GoalContribution.ContributionType.values:
        raise ValidationError("Goal contribution type is invalid.")
    scheduled = contribution_type == GoalContribution.ContributionType.SCHEDULED
    if scheduled != (occurrence is not None):
        raise ValidationError("Scheduled contributions require their scheduled occurrence.")
    uses_reserve = contribution_type in (
        GoalContribution.ContributionType.RESERVE,
        GoalContribution.ContributionType.AUTOMATIC,
    )
    if uses_reserve != (reserve_entry is not None):
        raise ValidationError("Reserve contribution types require a reserve allocation entry.")
    if reserve_entry is not None:
        if reserve_entry.household_id != locked.household_id or -reserve_entry.amount != normalized:
            raise ValidationError("The reserve allocation does not match this goal contribution.")
    description = f"Goal contribution · {revision.name}"
    if revision.goal_type == GoalRevision.GoalType.DEBT_PAYOFF:
        if revision.linked_debt is None or revision.linked_debt.financial_account is None:
            raise ValidationError("The debt-payoff goal is missing its liability account.")
        entry = record_debt_payment(
            household=locked.household,
            actor=actor,
            source=revision.source_account,
            liability=revision.linked_debt.financial_account,
            amount=normalized,
            effective_at=effective_at,
            description=description,
            request_id=request_id,
            note=reason,
            idempotency_key=_contribution_idempotency(locked, request_id),
        )
    else:
        if revision.destination_account is None:
            raise ValidationError("The goal is missing its destination account.")
        entry = record_ledger_goal_contribution(
            household=locked.household,
            actor=actor,
            source=revision.source_account,
            destination=revision.destination_account,
            amount=normalized,
            effective_at=effective_at,
            description=description,
            request_id=request_id,
            note=reason,
            idempotency_key=_contribution_idempotency(locked, request_id),
        )
    if occurrence is not None:
        plan = GoalFundingPlan.objects.filter(goal=locked).first()
        if plan is None or occurrence.source_id != plan.source_id:
            raise ValidationError("The occurrence does not belong to this goal.")
        reconcile_occurrence(
            occurrence=occurrence,
            journal_entry=entry,
            amount=normalized,
            actor=actor,
            request_id=request_id,
        )
    contribution = GoalContribution(
        goal=locked,
        pay_period=period,
        occurrence=occurrence,
        journal_entry=entry,
        reserve_entry=reserve_entry,
        contribution_type=contribution_type,
        amount=normalized,
        effective_at=effective_at,
        reason=reason.strip(),
        created_by=actor,
    )
    _save_record(contribution)
    append_event(
        household=locked.household,
        actor=actor,
        action="goal.contribution_recorded",
        entity_type="goal_contribution",
        entity_id=contribution.pk,
        request_id=request_id,
        after={
            "goal_id": locked.pk,
            "pay_period_id": period.pk,
            "journal_entry_id": entry.pk,
            "reserve_entry_id": reserve_entry.pk if reserve_entry else None,
            "occurrence_id": occurrence.pk if occurrence else None,
            "contribution_type": contribution.contribution_type,
            "amount": contribution.amount,
            "current_amount": goal_current_amount(locked),
        },
        reason=reason.strip(),
    )
    return contribution


def preview_reserve_allocation(
    *,
    goal: Goal,
    posting_period: PayPeriod,
    amount: Decimal,
) -> ReserveAllocationPreview:
    if posting_period.household_id != goal.household_id:
        raise ValidationError("The reserve allocation period belongs to another household.")
    normalized = _money(amount, label="Reserve allocation", positive=True)
    before = reserve_balance(goal.household)
    if normalized > before:
        raise ValidationError("The allocation cannot exceed the current Household Reserve.")
    goal_before = goal_current_amount(goal)
    today = timezone.localdate(timezone=ZoneInfo(goal.household.time_zone))
    posting_date = today if posting_period.contains(today) else posting_period.start_date
    revision = current_goal_revision(goal, on_date=posting_date)
    payload: dict[str, object] = {
        "goal_id": str(goal.pk),
        "posting_period_id": str(posting_period.pk),
        "amount": format(normalized, "f"),
        "reserve_before": format(before, "f"),
        "goal_before": format(goal_before, "f"),
        "goal_revision_id": str(revision.pk),
    }
    return ReserveAllocationPreview(
        goal=goal,
        amount=normalized,
        reserve_before=before,
        reserve_after=before - normalized,
        goal_before=goal_before,
        goal_after=goal_before + normalized,
        fingerprint=_fingerprint(payload),
    )


@transaction.atomic
def allocate_reserve_to_goal(
    *,
    goal: Goal,
    actor: User,
    posting_period: PayPeriod,
    amount: Decimal,
    expected_preview_fingerprint: str,
    request_id: str,
    reason: str,
    automatic: bool = False,
) -> GoalContribution:
    require_household_membership(actor, goal.household)
    Household.objects.select_for_update().get(pk=goal.household_id)
    locked_goal = Goal.objects.select_for_update().select_related("household").get(pk=goal.pk)
    if not reason.strip():
        raise ValidationError("Reserve allocations require a reason.")
    preview = preview_reserve_allocation(
        goal=locked_goal,
        posting_period=posting_period,
        amount=amount,
    )
    if preview.fingerprint != expected_preview_fingerprint:
        raise ValidationError("The reserve allocation preview is stale; preview it again.")
    today = timezone.localdate(timezone=ZoneInfo(locked_goal.household.time_zone))
    posting_date = today if posting_period.contains(today) else posting_period.start_date
    revision = current_goal_revision(locked_goal, on_date=posting_date)
    if revision.status == GoalRevision.Status.COMPLETED:
        raise ValidationError("Completed goals cannot receive reserve allocations.")
    if automatic and not revision.automatic_excess_allocation:
        raise ValidationError("This goal is not eligible for automatic excess allocation.")
    remaining = max(revision.target_amount - preview.goal_before, Decimal("0.00"))
    if preview.amount > remaining:
        raise ValidationError("The reserve allocation cannot exceed the remaining goal target.")
    reserve_entry = allocate_reserve(
        household=locked_goal.household,
        actor=actor,
        posting_period=posting_period,
        amount=preview.amount,
        allocation_label=f"Goal · {revision.name}",
        request_id=request_id,
        reason=reason,
    )
    effective_at = timezone.make_aware(
        datetime.combine(posting_date, datetime.min.time()),
        ZoneInfo(locked_goal.household.time_zone),
    )
    return record_goal_contribution(
        goal=locked_goal,
        actor=actor,
        pay_period=posting_period,
        amount=preview.amount,
        effective_at=effective_at,
        request_id=request_id,
        reason=reason,
        contribution_type=(
            GoalContribution.ContributionType.AUTOMATIC
            if automatic
            else GoalContribution.ContributionType.RESERVE
        ),
        reserve_entry=reserve_entry,
    )


def preview_priority_allocation(
    *,
    household: Household,
    posting_period: PayPeriod,
    amount: Decimal | None = None,
) -> PriorityAllocationPreview:
    if posting_period.household_id != household.pk:
        raise ValidationError("The reserve allocation period belongs to another household.")
    before = reserve_balance(household)
    limit = before if amount is None else _money(amount, label="Priority allocation", positive=True)
    if limit > before:
        raise ValidationError("The allocation cannot exceed the current Household Reserve.")
    remaining_limit = limit
    today = timezone.localdate(timezone=ZoneInfo(household.time_zone))
    posting_date = today if posting_period.contains(today) else posting_period.start_date
    rows = goal_progress_rows(household=household, on_date=posting_date)
    allocations: list[PriorityAllocationItem] = []
    for row in rows:
        if remaining_limit <= 0:
            break
        if (
            row.revision.status != GoalRevision.Status.ACTIVE
            or not row.revision.automatic_excess_allocation
            or row.remaining_amount <= 0
        ):
            continue
        allocation = min(row.remaining_amount, remaining_limit)
        allocations.append(PriorityAllocationItem(row.goal, row.revision, allocation))
        remaining_limit -= allocation
    total = sum((item.amount for item in allocations), Decimal("0.00"))
    payload: dict[str, object] = {
        "posting_period_id": str(posting_period.pk),
        "reserve_before": format(before, "f"),
        "limit": format(limit, "f"),
        "allocations": [
            [str(item.goal.pk), str(item.revision.pk), format(item.amount, "f")]
            for item in allocations
        ],
    }
    return PriorityAllocationPreview(
        allocations=tuple(allocations),
        reserve_before=before,
        reserve_after=before - total,
        fingerprint=_fingerprint(payload),
    )


@transaction.atomic
def allocate_reserve_by_priority(
    *,
    household: Household,
    actor: User,
    posting_period: PayPeriod,
    amount: Decimal | None,
    expected_preview_fingerprint: str,
    request_id: str,
    reason: str,
) -> tuple[GoalContribution, ...]:
    require_household_membership(actor, household)
    locked_household = Household.objects.select_for_update().get(pk=household.pk)
    if not reason.strip():
        raise ValidationError("Priority reserve allocations require a reason.")
    preview = preview_priority_allocation(
        household=locked_household,
        posting_period=posting_period,
        amount=amount,
    )
    if preview.fingerprint != expected_preview_fingerprint:
        raise ValidationError("The priority allocation preview is stale; preview it again.")
    if not preview.allocations:
        raise ValidationError("No active goals are eligible for automatic excess allocation.")
    contributions: list[GoalContribution] = []
    for item in preview.allocations:
        item_preview = preview_reserve_allocation(
            goal=item.goal,
            posting_period=posting_period,
            amount=item.amount,
        )
        contributions.append(
            allocate_reserve_to_goal(
                goal=item.goal,
                actor=actor,
                posting_period=posting_period,
                amount=item.amount,
                expected_preview_fingerprint=item_preview.fingerprint,
                request_id=request_id,
                reason=reason,
                automatic=True,
            )
        )
    append_event(
        household=locked_household,
        actor=actor,
        action="goal.priority_reserve_allocation_completed",
        entity_type="goal_allocation_batch",
        entity_id=request_id,
        request_id=request_id,
        after={
            "posting_period_id": posting_period.pk,
            "goal_count": len(contributions),
            "amount": sum((item.amount for item in contributions), Decimal("0.00")),
            "remaining_reserve": reserve_balance(locked_household),
        },
        reason=reason.strip(),
    )
    return tuple(contributions)
