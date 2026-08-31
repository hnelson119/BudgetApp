from __future__ import annotations

from datetime import date
from typing import Any
from uuid import UUID
from zoneinfo import ZoneInfo

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core import signing
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone

from budgets.forms import (
    CategoryForm,
    FixedExpenseScheduleForm,
    OccurrenceCancelForm,
    OccurrenceMoveForm,
    OccurrenceOverrideForm,
    ReconciliationForm,
    ReserveAllocationForm,
    VariableBudgetForm,
)
from budgets.models import VariableBudget
from budgets.services.reconciliation import reconcile_occurrence
from budgets.services.summary import build_period_summary, period_occurrences
from budgets.services.variable_budgets import delete_variable_budget, set_variable_budget
from households.models import Category, Household
from households.services.access import get_active_household
from households.services.categories import create_category
from identity.models import User
from periods.models import PayPeriod
from reserves.services import allocate_reserve
from schedules.models import Occurrence, RecurringSource
from schedules.services import (
    cancel_occurrence,
    cancel_occurrence_and_future,
    create_recurring_source,
    move_occurrence,
    override_occurrence,
    preview_revision,
    synchronize_occurrences,
)

_VARIABLE_BUDGET_VERSION_SALT = "budgets.variable-create-versions.v1"


def _request_id(request: HttpRequest) -> str:
    return str(request.request_id)  # type: ignore[attr-defined]


def _today(household: Household) -> date:
    return timezone.localdate(timezone=ZoneInfo(household.time_zone))


def _variable_budget_version_snapshot(period: PayPeriod) -> str:
    versions = {
        str(category_id): updated_at.isoformat()
        for category_id, updated_at in VariableBudget.objects.filter(pay_period=period).values_list(
            "category_id", "updated_at"
        )
    }
    return signing.dumps(versions, salt=_VARIABLE_BUDGET_VERSION_SALT, compress=True)


def _expected_snapshot_version(token: str, category: Category) -> str:
    try:
        versions = signing.loads(
            token,
            salt=_VARIABLE_BUDGET_VERSION_SALT,
            max_age=12 * 60 * 60,
        )
    except signing.BadSignature as error:
        raise ValidationError(
            "This category budget form is no longer valid; refresh and try again."
        ) from error
    if not isinstance(versions, dict):
        raise ValidationError("This category budget form is invalid; refresh and try again.")
    expected_version = versions.get(str(category.pk), "")
    if not isinstance(expected_version, str):
        raise ValidationError("This category budget form is invalid; refresh and try again.")
    return expected_version


def _period_context(household: Household, period: PayPeriod) -> dict[str, Any]:
    return {
        "period": period,
        "previous_period": PayPeriod.objects.filter(
            household=household,
            start_date__lt=period.start_date,
        )
        .order_by("-start_date")
        .first(),
        "next_period": PayPeriod.objects.filter(
            household=household,
            start_date__gt=period.start_date,
        )
        .order_by("start_date")
        .first(),
    }


def _budget_url(period: PayPeriod | None) -> str:
    if period is None:
        raise Http404("The scheduled item is not assigned to a paycheck period.")
    return reverse("budgets:detail", args=(period.pk,))


def _actor(request: HttpRequest) -> User:
    if not isinstance(request.user, User):
        raise PermissionDenied
    return request.user


def _add_domain_error(form: Any, error: ValidationError) -> None:
    form.add_error(None, error)


@login_required
def detail(request: HttpRequest, period_id: str) -> HttpResponse:
    household = get_active_household(request)
    period = get_object_or_404(PayPeriod, pk=period_id, household=household)
    today = _today(household)
    occurrences = period_occurrences(period, include_cancelled=True)
    query = request.GET.get("q", "").strip()[:120]
    kind = request.GET.get("kind", "").strip()
    status = request.GET.get("status", "").strip()
    category_id = request.GET.get("category", "").strip()
    if query:
        occurrences = occurrences.filter(source__name__icontains=query)
    if kind in RecurringSource.Kind.values:
        occurrences = occurrences.filter(source__kind=kind)
    if status in Occurrence.Status.values:
        occurrences = occurrences.filter(status=status)
    try:
        category_uuid = UUID(category_id) if category_id else None
    except (TypeError, ValueError, AttributeError):
        category_uuid = None
        category_id = ""
    if category_uuid is not None:
        occurrences = occurrences.filter(source__expense_detail__category_id=category_uuid)
    occurrence_list = list(occurrences)
    groups = tuple(
        {
            "kind": group_kind,
            "label": label,
            "items": tuple(item for item in occurrence_list if item.source.kind == group_kind),
        }
        for group_kind, label in RecurringSource.Kind.choices
    )
    context = {
        "household": household,
        "summary": build_period_summary(household=household, period=period, today=today),
        "groups": groups,
        "categories": Category.objects.filter(household=household, is_archived=False),
        "status_choices": Occurrence.Status.choices,
        "kind_choices": RecurringSource.Kind.choices,
        "filters": {"q": query, "kind": kind, "status": status, "category": category_id},
        "today": today,
        "current_nav": "budget",
        **_period_context(household, period),
    }
    return render(request, "budgets/detail.html", context)


@login_required
def variable_budget_create(request: HttpRequest, period_id: str) -> HttpResponse:
    household = get_active_household(request)
    period = get_object_or_404(PayPeriod, pk=period_id, household=household)
    form = VariableBudgetForm(
        request.POST or None,
        household=household,
        initial={"expected_version": _variable_budget_version_snapshot(period)},
    )
    if request.method == "POST" and form.is_valid():
        try:
            expected_version = _expected_snapshot_version(
                form.cleaned_data["expected_version"],
                form.cleaned_data["category"],
            )
            set_variable_budget(
                pay_period=period,
                category=form.cleaned_data["category"],
                planned_amount=form.cleaned_data["planned_amount"],
                notes=form.cleaned_data["notes"],
                actor=_actor(request),
                request_id=_request_id(request),
                expected_version=expected_version,
            )
        except ValidationError as error:
            _add_domain_error(form, error)
        else:
            messages.success(request, "Category budget saved.")
            return redirect(_budget_url(period))
    return render(
        request,
        "budgets/form.html",
        {
            "household": household,
            "period": period,
            "form": form,
            "title": "Add category budget",
            "current_nav": "budget",
        },
    )


@login_required
def variable_budget_edit(request: HttpRequest, budget_id: str) -> HttpResponse:
    household = get_active_household(request)
    budget = get_object_or_404(
        VariableBudget.objects.select_related("pay_period", "category"),
        pk=budget_id,
        pay_period__household=household,
    )
    form = VariableBudgetForm(
        request.POST or None,
        household=household,
        initial={
            "category": budget.category,
            "planned_amount": budget.planned_amount,
            "notes": budget.notes,
            "expected_version": budget.updated_at.isoformat(),
        },
    )
    form.fields["category"].disabled = True
    if request.method == "POST" and form.is_valid():
        try:
            set_variable_budget(
                pay_period=budget.pay_period,
                category=budget.category,
                planned_amount=form.cleaned_data["planned_amount"],
                notes=form.cleaned_data["notes"],
                actor=_actor(request),
                request_id=_request_id(request),
                expected_version=form.cleaned_data["expected_version"],
            )
        except ValidationError as error:
            _add_domain_error(form, error)
        else:
            messages.success(request, "Category budget updated for this paycheck period.")
            return redirect(_budget_url(budget.pay_period))
    return render(
        request,
        "budgets/form.html",
        {
            "household": household,
            "period": budget.pay_period,
            "form": form,
            "title": f"Edit {budget.category.name}",
            "budget": budget,
            "current_nav": "budget",
        },
    )


@login_required
def variable_budget_delete(request: HttpRequest, budget_id: str) -> HttpResponse:
    household = get_active_household(request)
    budget = get_object_or_404(
        VariableBudget.objects.select_related("pay_period", "category"),
        pk=budget_id,
        pay_period__household=household,
    )
    error = ""
    if request.method == "POST":
        reason = request.POST.get("reason", "")[:500]
        confirmed = request.POST.get("confirm") == "on"
        if not confirmed:
            error = "Confirm that you want to remove this period-specific budget."
        else:
            try:
                delete_variable_budget(
                    variable_budget=budget,
                    actor=_actor(request),
                    request_id=_request_id(request),
                    reason=reason,
                )
            except ValidationError as exception:
                error = "; ".join(exception.messages)
            else:
                messages.success(request, "Category budget removed. The audit record was retained.")
                return redirect(_budget_url(budget.pay_period))
    return render(
        request,
        "budgets/confirm_delete.html",
        {
            "household": household,
            "period": budget.pay_period,
            "budget": budget,
            "error": error,
            "current_nav": "budget",
        },
    )


@login_required
def category_create(request: HttpRequest, period_id: str) -> HttpResponse:
    household = get_active_household(request)
    period = get_object_or_404(PayPeriod, pk=period_id, household=household)
    form = CategoryForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            create_category(
                household=household,
                actor=_actor(request),
                name=form.cleaned_data["name"],
                color=form.cleaned_data["color"],
                sort_order=form.cleaned_data["sort_order"],
                request_id=_request_id(request),
            )
        except ValidationError as error:
            _add_domain_error(form, error)
        else:
            messages.success(request, "Spending category created.")
            return redirect(reverse("budgets:variable-create", args=(period.pk,)))
    return render(
        request,
        "budgets/form.html",
        {
            "household": household,
            "period": period,
            "form": form,
            "title": "Create category",
            "current_nav": "budget",
        },
    )


def _occurrence_for_household(household: Household, occurrence_id: str) -> Occurrence:
    return get_object_or_404(
        Occurrence.objects.select_related("source", "pay_period", "source__household"),
        pk=occurrence_id,
        source__household=household,
    )


@login_required
def occurrence_edit(request: HttpRequest, occurrence_id: str) -> HttpResponse:
    household = get_active_household(request)
    occurrence = _occurrence_for_household(household, occurrence_id)
    form = OccurrenceOverrideForm(
        request.POST or None,
        initial={
            "planned_amount": occurrence.planned_amount,
            "expected_date": occurrence.expected_date,
        },
    )
    if request.method == "POST" and form.is_valid():
        try:
            override_occurrence(
                occurrence=occurrence,
                actor=_actor(request),
                request_id=_request_id(request),
                reason=form.cleaned_data["reason"],
                planned_amount=form.cleaned_data["planned_amount"],
                expected_date=form.cleaned_data["expected_date"],
            )
        except ValidationError as error:
            _add_domain_error(form, error)
        else:
            messages.success(
                request, "This paycheck-period item was updated; its schedule is unchanged."
            )
            return redirect(_budget_url(occurrence.pay_period))
    return render(
        request,
        "budgets/occurrence_form.html",
        {
            "household": household,
            "period": occurrence.pay_period,
            "occurrence": occurrence,
            "form": form,
            "action": "Edit this pay period only",
            "current_nav": "budget",
        },
    )


@login_required
def occurrence_move_view(request: HttpRequest, occurrence_id: str) -> HttpResponse:
    household = get_active_household(request)
    occurrence = _occurrence_for_household(household, occurrence_id)
    form = OccurrenceMoveForm(
        request.POST or None,
        household=household,
        occurrence=occurrence,
    )
    if request.method == "POST" and form.is_valid():
        old_period = occurrence.pay_period
        try:
            move_occurrence(
                occurrence=occurrence,
                target_period=form.cleaned_data["target_period"],
                actor=_actor(request),
                request_id=_request_id(request),
                reason=form.cleaned_data["reason"],
            )
        except ValidationError as error:
            _add_domain_error(form, error)
        else:
            messages.success(request, "The item was moved once; future occurrences are unchanged.")
            return redirect(_budget_url(old_period))
    return render(
        request,
        "budgets/occurrence_form.html",
        {
            "household": household,
            "period": occurrence.pay_period,
            "occurrence": occurrence,
            "form": form,
            "action": "Move this occurrence",
            "current_nav": "budget",
        },
    )


@login_required
def occurrence_cancel_view(request: HttpRequest, occurrence_id: str) -> HttpResponse:
    household = get_active_household(request)
    occurrence = _occurrence_for_household(household, occurrence_id)
    form = OccurrenceCancelForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            if form.cleaned_data["scope"] == "future":
                cancel_occurrence_and_future(
                    occurrence=occurrence,
                    actor=_actor(request),
                    request_id=_request_id(request),
                    reason=form.cleaned_data["reason"],
                )
                message = "This and future occurrences were cancelled; completed history remains."
            else:
                cancel_occurrence(
                    occurrence=occurrence,
                    actor=_actor(request),
                    request_id=_request_id(request),
                    reason=form.cleaned_data["reason"],
                )
                message = "Only this occurrence was cancelled."
        except ValidationError as error:
            _add_domain_error(form, error)
        else:
            messages.success(request, message)
            return redirect(_budget_url(occurrence.pay_period))
    return render(
        request,
        "budgets/occurrence_form.html",
        {
            "household": household,
            "period": occurrence.pay_period,
            "occurrence": occurrence,
            "form": form,
            "action": "Cancel scheduled item",
            "is_destructive": True,
            "current_nav": "budget",
        },
    )


@login_required
def occurrence_reconcile(request: HttpRequest, occurrence_id: str) -> HttpResponse:
    household = get_active_household(request)
    occurrence = _occurrence_for_household(household, occurrence_id)
    form = ReconciliationForm(
        request.POST or None,
        household=household,
        occurrence=occurrence,
        initial={"amount": occurrence.planned_amount},
    )
    if request.method == "POST" and form.is_valid():
        try:
            reconcile_occurrence(
                occurrence=occurrence,
                journal_entry=form.cleaned_data["journal_entry"],
                amount=form.cleaned_data["amount"],
                actor=_actor(request),
                request_id=_request_id(request),
            )
        except ValidationError as error:
            _add_domain_error(form, error)
        else:
            messages.success(request, "Actual transaction linked to the planned item.")
            return redirect(_budget_url(occurrence.pay_period))
    return render(
        request,
        "budgets/occurrence_form.html",
        {
            "household": household,
            "period": occurrence.pay_period,
            "occurrence": occurrence,
            "form": form,
            "action": "Reconcile actual transaction",
            "current_nav": "budget",
        },
    )


@login_required
def reserve_allocate(request: HttpRequest, period_id: str) -> HttpResponse:
    household = get_active_household(request)
    period = get_object_or_404(PayPeriod, pk=period_id, household=household)
    form = ReserveAllocationForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            allocate_reserve(
                household=household,
                actor=_actor(request),
                posting_period=period,
                amount=form.cleaned_data["amount"],
                allocation_label=form.cleaned_data["allocation_label"],
                reason=form.cleaned_data["reason"],
                request_id=_request_id(request),
            )
        except ValidationError as error:
            _add_domain_error(form, error)
        else:
            messages.success(request, "Reserve allocation recorded as protected history.")
            return redirect(reverse("core:home") + f"?period={period.pk}")
    return render(
        request,
        "budgets/form.html",
        {
            "household": household,
            "period": period,
            "form": form,
            "title": "Allocate Household Reserve",
            "help_text": (
                "This reduces the allocation reserve. It is not new income "
                "or a verified bank transfer."
            ),
            "current_nav": "overview",
        },
    )


@login_required
def fixed_expense_create(request: HttpRequest, period_id: str) -> HttpResponse:
    household = get_active_household(request)
    period = get_object_or_404(PayPeriod, pk=period_id, household=household)
    form = FixedExpenseScheduleForm(
        request.POST or None,
        household=household,
        initial={"start_date": period.start_date},
    )
    preview = None
    if request.method == "POST" and form.is_valid():
        try:
            spec = form.revision_spec()
            preview = preview_revision(spec, preview_from=spec.effective_from)
            if request.POST.get("action") == "confirm":
                with transaction.atomic():
                    create_recurring_source(
                        household=household,
                        actor=_actor(request),
                        kind=RecurringSource.Kind.FIXED_EXPENSE,
                        name=form.cleaned_data["name"],
                        notes=form.cleaned_data["notes"],
                        revision_spec=spec,
                        expected_preview_fingerprint=form.cleaned_data["preview_fingerprint"],
                        expense_category=form.cleaned_data["category"],
                        is_required_expense=form.cleaned_data["is_required"],
                        request_id=_request_id(request),
                    )
                    periods = PayPeriod.objects.filter(household=household).order_by("start_date")
                    first_period = periods.first()
                    last_period = periods.last()
                    if first_period is not None and last_period is not None:
                        synchronize_occurrences(
                            household=household,
                            actor=_actor(request),
                            window_start=first_period.start_date,
                            window_end=last_period.display_end_date,
                            request_id=_request_id(request),
                        )
                messages.success(request, "Fixed expense saved and synced into paycheck periods.")
                return redirect(_budget_url(period))
            form.fields["preview_fingerprint"].initial = preview.fingerprint
        except ValidationError as error:
            _add_domain_error(form, error)
    return render(
        request,
        "budgets/fixed_expense_form.html",
        {
            "household": household,
            "period": period,
            "form": form,
            "preview": preview,
            "current_nav": "budget",
        },
    )
