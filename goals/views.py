from __future__ import annotations

import logging
from dataclasses import replace
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from zoneinfo import ZoneInfo

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_GET, require_http_methods

from goals.forms import (
    GoalContributionForm,
    GoalForm,
    GoalStatusForm,
    PriorityAllocationForm,
    ReserveAllocationForm,
    contribution_type_for_occurrence,
)
from goals.models import Goal, GoalFundingPlan, GoalRevision
from goals.services import (
    GoalProgress,
    GoalSpec,
    allocate_reserve_by_priority,
    allocate_reserve_to_goal,
    create_goal,
    goal_progress_rows,
    preview_goal,
    preview_priority_allocation,
    preview_reserve_allocation,
    record_goal_contribution,
    revise_goal,
)
from households.models import Household
from households.services.access import get_active_household
from identity.models import User
from periods.models import PayPeriod
from reserves.services import reserve_balance
from schedules.models import Occurrence

security_logger = logging.getLogger("security")


def _actor(request: HttpRequest) -> User:
    if not isinstance(request.user, User):
        raise PermissionDenied
    return request.user


def _request_id(request: HttpRequest) -> str:
    return str(request.request_id)  # type: ignore[attr-defined]


def _today(household: Household) -> date:
    return timezone.localdate(timezone=ZoneInfo(household.time_zone))


def _goal(household: Household, goal_id: str) -> Goal:
    return get_object_or_404(
        Goal.objects.filter(household=household).prefetch_related("revisions", "contributions"),
        pk=goal_id,
    )


def _period(household: Household, period_id: str | None, *, on_date: date) -> PayPeriod:
    periods = PayPeriod.objects.filter(household=household)
    if period_id:
        return get_object_or_404(periods, pk=period_id)
    available = periods.exclude(status=PayPeriod.Status.CLOSED)
    selected = available.filter(start_date__lte=on_date, next_start_date__gt=on_date).first()
    if selected is None:
        selected = available.filter(start_date__gt=on_date).order_by("start_date").first()
    if selected is None:
        raise Http404("No paycheck period is available.")
    return selected


def _spec_from_revision(revision: GoalRevision, *, effective_from: date) -> GoalSpec:
    return GoalSpec(
        effective_from=effective_from,
        name=revision.name,
        goal_type=revision.goal_type,
        target_amount=revision.target_amount,
        target_date=revision.target_date,
        contribution_per_period=revision.contribution_per_period,
        priority=revision.priority,
        status=revision.status,
        automatic_excess_allocation=revision.automatic_excess_allocation,
        source_account=revision.source_account,
        destination_account=revision.destination_account,
        linked_debt=revision.linked_debt,
        notes=revision.notes,
    )


def _initial_from_revision(revision: GoalRevision, *, effective_from: date) -> dict[str, object]:
    return {
        "effective_from": effective_from,
        "name": revision.name,
        "goal_type": revision.goal_type,
        "target_amount": revision.target_amount,
        "target_date": revision.target_date,
        "contribution_per_period": revision.contribution_per_period,
        "priority": revision.priority,
        "status": revision.status,
        "automatic_excess_allocation": revision.automatic_excess_allocation,
        "source_account": revision.source_account,
        "destination_account": revision.destination_account,
        "linked_debt": revision.linked_debt,
        "notes": revision.notes,
    }


@login_required
@require_GET
def goal_list(request: HttpRequest) -> HttpResponse:
    household = get_active_household(request)
    today = _today(household)
    period = _period(household, request.GET.get("period"), on_date=today)
    rows = goal_progress_rows(household=household, on_date=today)
    return render(
        request,
        "goals/goal_list.html",
        {
            "household": household,
            "period": period,
            "rows": rows,
            "active_count": sum(row.revision.status == GoalRevision.Status.ACTIVE for row in rows),
            "total_current": sum((row.current_amount for row in rows), Decimal("0.00")),
            "total_target": sum((row.revision.target_amount for row in rows), Decimal("0.00")),
            "household_reserve": reserve_balance(household),
            "eligible_count": sum(
                row.revision.status == GoalRevision.Status.ACTIVE
                and row.revision.automatic_excess_allocation
                for row in rows
            ),
            "current_nav": "goals",
        },
    )


@login_required
@require_http_methods(("GET", "POST"))
def goal_create(request: HttpRequest) -> HttpResponse:
    household = get_active_household(request)
    today = _today(household)
    current_period = _period(household, None, on_date=today)
    form = GoalForm(
        request.POST or None,
        household=household,
        initial={
            "effective_from": current_period.start_date,
            "opening_amount": Decimal("0.00"),
            "contribution_per_period": Decimal("0.00"),
            "priority": 1,
            "status": GoalRevision.Status.ACTIVE,
            "automatic_excess_allocation": False,
        },
    )
    preview = None
    if request.method == "POST" and form.is_valid():
        try:
            spec = form.goal_spec()
            opening = form.cleaned_data["opening_amount"]
            preview = preview_goal(household=household, spec=spec, opening_amount=opening)
            if request.POST.get("action") == "confirm":
                goal, _ = create_goal(
                    household=household,
                    actor=_actor(request),
                    spec=spec,
                    opening_amount=opening,
                    expected_preview_fingerprint=str(form.cleaned_data["preview_fingerprint"]),
                    request_id=_request_id(request),
                )
                messages.success(
                    request,
                    "Goal saved with protected history and paycheck-period funding.",
                )
                return redirect("goals:detail", goal_id=goal.pk)
        except ValidationError as error:
            security_logger.warning(
                "Goal submission rejected.",
                extra={
                    "event": "goal.create_rejected",
                    "method": request.method,
                    "error_reference": _request_id(request),
                },
            )
            form.add_error(None, error)
    elif request.method == "POST":
        security_logger.warning(
            "Goal submission rejected.",
            extra={
                "event": "goal.create_rejected",
                "method": request.method,
                "error_reference": _request_id(request),
            },
        )
    return render(
        request,
        "goals/goal_form.html",
        {
            "household": household,
            "period": current_period,
            "form": form,
            "preview": preview,
            "title": "Add goal",
            "current_nav": "goals",
        },
    )


def _progress_for_goal(household: Household, goal: Goal, on_date: date) -> GoalProgress:
    progress = next(
        (
            row
            for row in goal_progress_rows(household=household, on_date=on_date)
            if row.goal == goal
        ),
        None,
    )
    if progress is None:
        raise Http404
    return progress


@login_required
@require_GET
def goal_detail(request: HttpRequest, goal_id: str) -> HttpResponse:
    household = get_active_household(request)
    today = _today(household)
    goal = _goal(household, goal_id)
    progress = _progress_for_goal(household, goal, today)
    period = _period(household, request.GET.get("period"), on_date=today)
    plan = GoalFundingPlan.objects.filter(goal=goal).select_related("source").first()
    occurrences: tuple[Occurrence, ...] = ()
    if plan is not None:
        occurrences = tuple(
            Occurrence.objects.filter(source=plan.source)
            .select_related("pay_period")
            .order_by("-expected_date")[:20]
        )
    return render(
        request,
        "goals/goal_detail.html",
        {
            "household": household,
            "period": period,
            "goal": goal,
            "progress": progress,
            "revisions": goal.revisions.select_related(
                "source_account", "destination_account", "linked_debt"
            ).order_by("-revision_number"),
            "contributions": goal.contributions.select_related(
                "pay_period", "journal_entry", "reserve_entry"
            ),
            "occurrences": occurrences,
            "household_reserve": reserve_balance(household),
            "current_nav": "goals",
        },
    )


@login_required
@require_http_methods(("GET", "POST"))
def goal_revise(request: HttpRequest, goal_id: str) -> HttpResponse:
    household = get_active_household(request)
    goal = _goal(household, goal_id)
    latest = goal.revisions.order_by("-revision_number").first()
    if latest is None:
        raise Http404
    effective_from = max(_today(household), latest.effective_from + timedelta(days=1))
    form = GoalForm(
        request.POST or None,
        household=household,
        is_revision=True,
        initial=_initial_from_revision(latest, effective_from=effective_from),
    )
    preview = None
    if request.method == "POST" and form.is_valid():
        try:
            spec = form.goal_spec()
            preview = preview_goal(household=household, spec=spec)
            if request.POST.get("action") == "confirm":
                revise_goal(
                    goal=goal,
                    actor=_actor(request),
                    spec=spec,
                    expected_preview_fingerprint=str(form.cleaned_data["preview_fingerprint"]),
                    request_id=_request_id(request),
                    reason=form.cleaned_data["reason"],
                )
                messages.success(
                    request,
                    "Goal revision saved; prior settings and completed funding remain protected.",
                )
                return redirect("goals:detail", goal_id=goal.pk)
        except ValidationError as error:
            security_logger.warning(
                "Goal revision rejected.",
                extra={
                    "event": "goal.revision_rejected",
                    "method": request.method,
                    "error_reference": _request_id(request),
                },
            )
            form.add_error(None, error)
    elif request.method == "POST":
        security_logger.warning(
            "Goal revision rejected.",
            extra={
                "event": "goal.revision_rejected",
                "method": request.method,
                "error_reference": _request_id(request),
            },
        )
    return render(
        request,
        "goals/goal_form.html",
        {
            "household": household,
            "goal": goal,
            "form": form,
            "preview": preview,
            "title": f"Revise {latest.name}",
            "is_revision": True,
            "current_nav": "goals",
        },
    )


@login_required
@require_http_methods(("GET", "POST"))
def goal_status(request: HttpRequest, goal_id: str, status: str) -> HttpResponse:
    household = get_active_household(request)
    if status not in GoalRevision.Status.values:
        raise Http404
    goal = _goal(household, goal_id)
    latest = (
        goal.revisions.select_related("source_account", "destination_account", "linked_debt")
        .order_by("-revision_number")
        .first()
    )
    if latest is None:
        raise Http404
    effective_from = max(_today(household), latest.effective_from + timedelta(days=1))
    form = GoalStatusForm(
        request.POST or None,
        initial={"effective_from": effective_from, "status": status},
    )
    form.fields["status"].disabled = True
    if request.method == "POST" and form.is_valid():
        try:
            spec = replace(
                _spec_from_revision(
                    latest,
                    effective_from=form.cleaned_data["effective_from"],
                ),
                status=status,
            )
            preview = preview_goal(household=household, spec=spec)
            revise_goal(
                goal=goal,
                actor=_actor(request),
                spec=spec,
                expected_preview_fingerprint=preview.fingerprint,
                request_id=_request_id(request),
                reason=form.cleaned_data["reason"],
            )
        except ValidationError as error:
            security_logger.warning(
                "Goal status change rejected.",
                extra={
                    "event": "goal.status_rejected",
                    "method": request.method,
                    "error_reference": _request_id(request),
                },
            )
            form.add_error(None, error)
        else:
            messages.success(
                request,
                f"Goal status changed to {GoalRevision.Status(status).label}.",
            )
            return redirect("goals:detail", goal_id=goal.pk)
    elif request.method == "POST":
        security_logger.warning(
            "Goal status change rejected.",
            extra={
                "event": "goal.status_rejected",
                "method": request.method,
                "error_reference": _request_id(request),
            },
        )
    return render(
        request,
        "goals/goal_status.html",
        {
            "household": household,
            "goal": goal,
            "revision": latest,
            "target_status": GoalRevision.Status(status).label,
            "form": form,
            "current_nav": "goals",
        },
    )


@login_required
@require_http_methods(("GET", "POST"))
def goal_contribute(
    request: HttpRequest,
    goal_id: str,
    occurrence_id: str | None = None,
) -> HttpResponse:
    household = get_active_household(request)
    goal = _goal(household, goal_id)
    occurrence = None
    occurrence_period = None
    if occurrence_id is not None:
        plan = get_object_or_404(GoalFundingPlan, goal=goal)
        occurrence = get_object_or_404(
            Occurrence.objects.select_related("pay_period"),
            pk=occurrence_id,
            source=plan.source,
        )
        occurrence_period = occurrence.pay_period
        if occurrence_period is None:
            raise Http404
    today = _today(household)
    default_period = occurrence_period or _period(household, None, on_date=today)
    default_date = occurrence.expected_date if occurrence is not None else today
    if not default_period.contains(default_date):
        default_date = default_period.start_date
    form = GoalContributionForm(
        request.POST or None,
        household=household,
        occurrence_period=occurrence_period,
        initial={
            "pay_period": default_period,
            "amount": occurrence.planned_amount if occurrence else Decimal("0.00"),
            "effective_date": default_date,
        },
    )
    if request.method == "POST" and form.is_valid():
        effective_at = timezone.make_aware(
            datetime.combine(form.cleaned_data["effective_date"], time(hour=12)),
            ZoneInfo(household.time_zone),
        )
        try:
            record_goal_contribution(
                goal=goal,
                actor=_actor(request),
                pay_period=form.cleaned_data["pay_period"],
                amount=form.cleaned_data["amount"],
                effective_at=effective_at,
                request_id=_request_id(request),
                idempotency_key=(f"goal-manual-{form.cleaned_data['submission_token'].hex}"),
                reason=form.cleaned_data["reason"],
                contribution_type=contribution_type_for_occurrence(occurrence is not None),
                occurrence=occurrence,
            )
        except ValidationError as error:
            security_logger.warning(
                "Goal contribution rejected.",
                extra={
                    "event": "goal.contribution_rejected",
                    "method": request.method,
                    "error_reference": _request_id(request),
                },
            )
            form.add_error(None, error)
        else:
            messages.success(request, "Goal contribution recorded as an account movement.")
            return redirect("goals:detail", goal_id=goal.pk)
    elif request.method == "POST":
        security_logger.warning(
            "Goal contribution rejected.",
            extra={
                "event": "goal.contribution_rejected",
                "method": request.method,
                "error_reference": _request_id(request),
            },
        )
    return render(
        request,
        "goals/contribution_form.html",
        {
            "household": household,
            "goal": goal,
            "occurrence": occurrence,
            "form": form,
            "current_nav": "goals",
        },
    )


@login_required
@require_http_methods(("GET", "POST"))
def goal_reserve_allocate(
    request: HttpRequest,
    goal_id: str,
    period_id: str,
) -> HttpResponse:
    household = get_active_household(request)
    goal = _goal(household, goal_id)
    period = _period(household, period_id, on_date=_today(household))
    form = ReserveAllocationForm(request.POST or None)
    preview = None
    if request.method == "POST" and form.is_valid():
        try:
            preview = preview_reserve_allocation(
                goal=goal,
                posting_period=period,
                amount=form.cleaned_data["amount"],
            )
            if request.POST.get("action") == "confirm":
                allocate_reserve_to_goal(
                    goal=goal,
                    actor=_actor(request),
                    posting_period=period,
                    amount=form.cleaned_data["amount"],
                    expected_preview_fingerprint=str(form.cleaned_data["preview_fingerprint"]),
                    request_id=_request_id(request),
                    reason=form.cleaned_data["reason"],
                )
                messages.success(
                    request,
                    "Reserve allocated to the goal without creating income or spending.",
                )
                return redirect("goals:detail", goal_id=goal.pk)
        except ValidationError as error:
            security_logger.warning(
                "Goal reserve allocation rejected.",
                extra={
                    "event": "goal.reserve_allocation_rejected",
                    "method": request.method,
                    "error_reference": _request_id(request),
                },
            )
            form.add_error(None, error)
    elif request.method == "POST":
        security_logger.warning(
            "Goal reserve allocation rejected.",
            extra={
                "event": "goal.reserve_allocation_rejected",
                "method": request.method,
                "error_reference": _request_id(request),
            },
        )
    return render(
        request,
        "goals/reserve_allocation_form.html",
        {
            "household": household,
            "period": period,
            "goal": goal,
            "form": form,
            "preview": preview,
            "current_nav": "goals",
        },
    )


@login_required
@require_http_methods(("GET", "POST"))
def priority_allocate(request: HttpRequest, period_id: str) -> HttpResponse:
    household = get_active_household(request)
    period = _period(household, period_id, on_date=_today(household))
    form = PriorityAllocationForm(request.POST or None)
    preview = None
    if request.method == "POST" and form.is_valid():
        try:
            preview = preview_priority_allocation(
                household=household,
                posting_period=period,
                amount=form.cleaned_data.get("amount"),
            )
            if request.POST.get("action") == "confirm":
                allocate_reserve_by_priority(
                    household=household,
                    actor=_actor(request),
                    posting_period=period,
                    amount=form.cleaned_data.get("amount"),
                    expected_preview_fingerprint=str(form.cleaned_data["preview_fingerprint"]),
                    request_id=_request_id(request),
                    reason=form.cleaned_data["reason"],
                )
                messages.success(request, "Reserve allocated in protected goal-priority order.")
                return redirect("goals:list")
        except ValidationError as error:
            security_logger.warning(
                "Goal priority allocation rejected.",
                extra={
                    "event": "goal.priority_allocation_rejected",
                    "method": request.method,
                    "error_reference": _request_id(request),
                },
            )
            form.add_error(None, error)
    elif request.method == "POST":
        security_logger.warning(
            "Goal priority allocation rejected.",
            extra={
                "event": "goal.priority_allocation_rejected",
                "method": request.method,
                "error_reference": _request_id(request),
            },
        )
    return render(
        request,
        "goals/priority_allocation_form.html",
        {
            "household": household,
            "period": period,
            "form": form,
            "preview": preview,
            "current_nav": "goals",
        },
    )
