from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from decimal import Decimal
from zoneinfo import ZoneInfo

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_GET, require_http_methods

from debts.forms import (
    DebtAccountCreateForm,
    DebtMetadataForm,
    DebtStatementCorrectionForm,
    DebtStatementForm,
    DebtStatusConfirmationForm,
    DebtTermsForm,
    PayoffScenarioForm,
)
from debts.models import DebtAccount, DebtStatement, DebtTermsRevision
from debts.services import (
    PayoffComparison,
    StrategyComparison,
    change_debt_status,
    compare_payoff_strategies,
    create_debt_account,
    current_debt_terms,
    projection_debts_from_accounts,
    reconcile_debt_statement,
    revise_debt_terms,
    update_debt_account,
)
from households.models import Household
from households.services.access import get_active_household
from identity.models import User


@dataclass(frozen=True, slots=True)
class DebtRow:
    debt: DebtAccount
    terms: DebtTermsRevision
    scheduled_payment: Decimal


@dataclass(frozen=True, slots=True)
class ComparisonRow:
    comparison: StrategyComparison
    label: str


_STRATEGY_LABELS = {
    "minimum_only": "Minimum payments only",
    "snowball": "Snowball",
    "avalanche": "Avalanche",
    "custom": "Custom priority",
}


def _actor(request: HttpRequest) -> User:
    if not isinstance(request.user, User):
        raise PermissionDenied
    return request.user


def _request_id(request: HttpRequest) -> str:
    return str(request.request_id)  # type: ignore[attr-defined]


def _today(household: Household) -> date:
    return timezone.localdate(timezone=ZoneInfo(household.time_zone))


def _debt(household: Household, debt_id: str) -> DebtAccount:
    return get_object_or_404(
        DebtAccount.objects.filter(household=household).select_related(
            "financial_account",
            "created_by",
            "updated_by",
        ),
        pk=debt_id,
    )


def _row(debt: DebtAccount, on_date: date) -> DebtRow:
    terms = current_debt_terms(debt, on_date=on_date)
    return DebtRow(
        debt=debt,
        terms=terms,
        scheduled_payment=terms.minimum_payment + terms.recurring_extra_payment,
    )


@login_required
@require_GET
def debt_list(request: HttpRequest) -> HttpResponse:
    household = get_active_household(request)
    today = _today(household)
    debts = tuple(
        DebtAccount.objects.filter(household=household)
        .select_related("financial_account")
        .prefetch_related("terms_revisions")
    )
    rows = tuple(_row(debt, today) for debt in debts)
    active_rows = tuple(row for row in rows if row.debt.is_active)
    total_balance = sum((row.debt.current_balance for row in active_rows), Decimal("0.00"))
    scheduled_payment = sum(
        (row.scheduled_payment for row in active_rows),
        Decimal("0.00"),
    )
    return render(
        request,
        "debts/debt_list.html",
        {
            "household": household,
            "rows": rows,
            "total_balance": total_balance,
            "scheduled_payment": scheduled_payment,
            "active_count": len(active_rows),
            "current_nav": "debts",
        },
    )


@login_required
@require_http_methods(("GET", "POST"))
def debt_create(request: HttpRequest) -> HttpResponse:
    household = get_active_household(request)
    form = DebtAccountCreateForm(request.POST or None, household=household)
    if request.method == "POST" and form.is_valid():
        try:
            debt, _ = create_debt_account(
                household=household,
                actor=_actor(request),
                name=form.cleaned_data["name"],
                debt_type=form.cleaned_data["debt_type"],
                opening_balance=form.cleaned_data["opening_balance"],
                terms=form.terms_spec(),
                financial_account=form.cleaned_data["financial_account"],
                notes=form.cleaned_data["notes"],
                request_id=_request_id(request),
            )
        except ValidationError as error:
            form.add_error(None, error)
        else:
            messages.success(request, "Debt account and initial terms added.")
            return redirect("debts:detail", debt_id=debt.pk)
    return render(
        request,
        "debts/debt_form.html",
        {
            "household": household,
            "form": form,
            "title": "Add debt",
            "eyebrow": "Debt foundation",
            "help_text": (
                "Use lender statement values. APR and payment terms are stored as an immutable "
                "effective-dated revision."
            ),
            "current_nav": "debts",
        },
    )


@login_required
@require_GET
def debt_detail(request: HttpRequest, debt_id: str) -> HttpResponse:
    household = get_active_household(request)
    debt = _debt(household, debt_id)
    terms = tuple(debt.terms_revisions.select_related("created_by").order_by("-effective_from"))
    statements = tuple(
        debt.statements.select_related("created_by", "supersedes").order_by(
            "-statement_date", "-created_at"
        )
    )
    current_terms = current_debt_terms(debt, on_date=_today(household))
    return render(
        request,
        "debts/debt_detail.html",
        {
            "household": household,
            "debt": debt,
            "current_terms": current_terms,
            "scheduled_payment": (
                current_terms.minimum_payment + current_terms.recurring_extra_payment
            ),
            "terms_revisions": terms,
            "statements": statements,
            "current_nav": "debts",
        },
    )


@login_required
@require_http_methods(("GET", "POST"))
def debt_edit(request: HttpRequest, debt_id: str) -> HttpResponse:
    household = get_active_household(request)
    debt = _debt(household, debt_id)
    form = DebtMetadataForm(
        request.POST or None,
        household=household,
        debt=debt,
        initial={
            "name": debt.name,
            "debt_type": debt.debt_type,
            "financial_account": debt.financial_account,
            "notes": debt.notes,
        },
    )
    if request.method == "POST" and form.is_valid():
        try:
            updated = update_debt_account(
                debt=debt,
                actor=_actor(request),
                name=form.cleaned_data["name"],
                debt_type=form.cleaned_data["debt_type"],
                financial_account=form.cleaned_data["financial_account"],
                notes=form.cleaned_data["notes"],
                request_id=_request_id(request),
                reason=form.cleaned_data["reason"],
            )
        except ValidationError as error:
            form.add_error(None, error)
        else:
            messages.success(request, "Debt account details updated with protected audit history.")
            return redirect("debts:detail", debt_id=updated.pk)
    return render(
        request,
        "debts/debt_form.html",
        {
            "household": household,
            "debt": debt,
            "form": form,
            "title": f"Edit {debt.name}",
            "eyebrow": "Audited metadata change",
            "help_text": "Payment and APR changes use a separate effective-dated terms revision.",
            "current_nav": "debts",
        },
    )


@login_required
@require_http_methods(("GET", "POST"))
def debt_terms_create(request: HttpRequest, debt_id: str) -> HttpResponse:
    household = get_active_household(request)
    debt = _debt(household, debt_id)
    latest = debt.terms_revisions.order_by("-revision_number").first()
    if latest is None:
        raise Http404
    next_date = max(_today(household), latest.effective_from + timedelta(days=1))
    form = DebtTermsForm(
        request.POST or None,
        household=household,
        initial={
            "effective_from": next_date,
            "annual_percentage_rate": latest.annual_percentage_rate,
            "interest_method": latest.interest_method,
            "day_count_basis": latest.day_count_basis,
            "minimum_payment": latest.minimum_payment,
            "recurring_extra_payment": latest.recurring_extra_payment,
            "due_day": latest.due_day,
            "custom_priority": latest.custom_priority,
            "projection_notes": latest.projection_notes,
        },
    )
    if request.method == "POST" and form.is_valid():
        try:
            revision = revise_debt_terms(
                debt=debt,
                actor=_actor(request),
                terms=form.terms_spec(),
                request_id=_request_id(request),
                reason=form.cleaned_data["reason"],
            )
        except ValidationError as error:
            form.add_error(None, error)
        else:
            messages.success(request, f"Debt terms revision {revision.revision_number} added.")
            return redirect("debts:detail", debt_id=debt.pk)
    return render(
        request,
        "debts/debt_form.html",
        {
            "household": household,
            "debt": debt,
            "form": form,
            "title": f"Revise {debt.name} terms",
            "eyebrow": "Effective-dated change",
            "help_text": (
                "The prior terms remain immutable and continue to explain old projections."
            ),
            "current_nav": "debts",
        },
    )


def _statement_initial(
    debt: DebtAccount, terms: DebtTermsRevision, on_date: date
) -> dict[str, object]:
    return {
        "statement_date": on_date,
        "statement_balance": debt.current_balance,
        "annual_percentage_rate": terms.annual_percentage_rate,
        "minimum_payment": terms.minimum_payment,
    }


@login_required
@require_http_methods(("GET", "POST"))
def debt_statement_create(request: HttpRequest, debt_id: str) -> HttpResponse:
    household = get_active_household(request)
    debt = _debt(household, debt_id)
    today = _today(household)
    terms = current_debt_terms(debt, on_date=today)
    form = DebtStatementForm(
        request.POST or None,
        household=household,
        initial=_statement_initial(debt, terms, today),
    )
    if request.method == "POST" and form.is_valid():
        try:
            reconcile_debt_statement(
                debt=debt,
                actor=_actor(request),
                statement=form.statement_spec(),
                request_id=_request_id(request),
            )
        except ValidationError as error:
            form.add_error(None, error)
        else:
            messages.success(request, "Lender statement reconciled and protected.")
            return redirect("debts:detail", debt_id=debt.pk)
    return render(
        request,
        "debts/debt_form.html",
        {
            "household": household,
            "debt": debt,
            "form": form,
            "title": f"Reconcile {debt.name}",
            "eyebrow": "Lender statement",
            "help_text": (
                "The statement balance becomes the current projection balance. Escrow, PMI, "
                "and fees remain separate cash-flow components."
            ),
            "current_nav": "debts",
        },
    )


@login_required
@require_http_methods(("GET", "POST"))
def debt_statement_correct(
    request: HttpRequest,
    debt_id: str,
    statement_id: str,
) -> HttpResponse:
    household = get_active_household(request)
    debt = _debt(household, debt_id)
    statement = get_object_or_404(
        DebtStatement.objects.filter(debt=debt).select_related("supersedes"),
        pk=statement_id,
    )
    if DebtStatement.objects.filter(supersedes=statement).exists():
        raise Http404
    form = DebtStatementCorrectionForm(
        request.POST or None,
        household=household,
        initial={
            "statement_date": statement.statement_date,
            "period_start": statement.period_start,
            "period_end": statement.period_end,
            "due_date": statement.due_date,
            "statement_balance": statement.statement_balance,
            "annual_percentage_rate": statement.annual_percentage_rate,
            "minimum_payment": statement.minimum_payment,
            "principal_paid": statement.principal_paid,
            "interest_charged": statement.interest_charged,
            "fees_charged": statement.fees_charged,
            "escrow_paid": statement.escrow_paid,
            "pmi_paid": statement.pmi_paid,
            "extra_principal_paid": statement.extra_principal_paid,
            "notes": statement.notes,
        },
    )
    if request.method == "POST" and form.is_valid():
        try:
            reconcile_debt_statement(
                debt=debt,
                actor=_actor(request),
                statement=form.statement_spec(),
                supersedes=statement,
                reason=form.cleaned_data["reason"],
                request_id=_request_id(request),
            )
        except ValidationError as error:
            form.add_error(None, error)
        else:
            messages.success(request, "Statement correction appended; the original was preserved.")
            return redirect("debts:detail", debt_id=debt.pk)
    return render(
        request,
        "debts/debt_form.html",
        {
            "household": household,
            "debt": debt,
            "form": form,
            "title": f"Correct {statement.statement_date:%Y-%m-%d} statement",
            "eyebrow": "Append-only correction",
            "help_text": "This creates a linked correction and never edits the original record.",
            "current_nav": "debts",
        },
    )


@login_required
@require_http_methods(("GET", "POST"))
def debt_status(request: HttpRequest, debt_id: str, action: str) -> HttpResponse:
    household = get_active_household(request)
    debt = _debt(household, debt_id)
    if action == "archive":
        target = DebtAccount.Status.ARCHIVED
        verb = "Archive"
    elif action == "restore":
        target = (
            DebtAccount.Status.ACTIVE if debt.current_balance > 0 else DebtAccount.Status.PAID_OFF
        )
        verb = "Restore"
    else:
        raise Http404
    form = DebtStatusConfirmationForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            updated = change_debt_status(
                debt=debt,
                actor=_actor(request),
                status=target,
                request_id=_request_id(request),
                reason=form.cleaned_data["reason"],
            )
        except ValidationError as error:
            form.add_error(None, error)
        else:
            messages.success(request, f"Debt status changed to {updated.get_status_display()}.")
            return redirect("debts:detail", debt_id=updated.pk)
    return render(
        request,
        "debts/debt_status.html",
        {
            "household": household,
            "debt": debt,
            "form": form,
            "verb": verb,
            "target_label": DebtAccount.Status(target).label,
            "current_nav": "debts",
        },
    )


@login_required
@require_GET
def payoff_comparison(request: HttpRequest) -> HttpResponse:
    household = get_active_household(request)
    today = _today(household)
    form = PayoffScenarioForm(
        request.GET or None,
        initial={"monthly_extra": Decimal("0.00"), "start_date": today, "maximum_years": 40},
    )
    debts = tuple(
        DebtAccount.objects.filter(household=household, status=DebtAccount.Status.ACTIVE)
        .prefetch_related("terms_revisions")
        .order_by("name")
    )
    projection_debts = projection_debts_from_accounts(debts)
    comparison: PayoffComparison | None = None
    comparison_rows: tuple[ComparisonRow, ...] = ()
    if request.GET and form.is_valid():
        try:
            comparison = compare_payoff_strategies(
                projection_debts,
                monthly_extra=form.cleaned_data["monthly_extra"],
                start_date=form.cleaned_data["start_date"],
                max_months=form.cleaned_data["maximum_years"] * 12,
            )
        except ValidationError as error:
            form.add_error(None, error)
        else:
            comparison_rows = tuple(
                ComparisonRow(row, _STRATEGY_LABELS[row.strategy.value])
                for row in comparison.strategies
            )
    return render(
        request,
        "debts/payoff_comparison.html",
        {
            "household": household,
            "form": form,
            "has_debts": bool(projection_debts),
            "total_balance": sum(
                (debt.opening_balance for debt in projection_debts),
                Decimal("0.00"),
            ),
            "comparison": comparison,
            "comparison_rows": comparison_rows,
            "current_nav": "debts",
        },
    )
