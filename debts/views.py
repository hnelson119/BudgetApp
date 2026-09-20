from __future__ import annotations

import logging
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
    ExtraPrincipalForm,
    MortgagePlanForm,
    PayoffScenarioForm,
)
from debts.models import (
    DebtAccount,
    DebtStatement,
    DebtTermsRevision,
    MortgageInstallmentRule,
    MortgagePaymentPlan,
    MortgagePlanRevision,
)
from debts.services import (
    PayoffComparison,
    StrategyComparison,
    change_debt_status,
    compare_payoff_strategies,
    create_debt_account,
    create_mortgage_plan,
    current_debt_terms,
    mortgage_components,
    preview_mortgage_plan,
    projection_debts_from_accounts,
    reconcile_debt_statement,
    revise_debt_terms,
    revise_mortgage_plan,
    set_one_off_extra_principal,
    update_debt_account,
)
from households.models import Household
from households.services.access import get_active_household
from identity.models import User
from schedules.models import Occurrence


@dataclass(frozen=True, slots=True)
class DebtRow:
    debt: DebtAccount
    terms: DebtTermsRevision
    scheduled_payment: Decimal


@dataclass(frozen=True, slots=True)
class ComparisonRow:
    comparison: StrategyComparison
    label: str


@dataclass(frozen=True, slots=True)
class MortgageRevisionRow:
    revision: MortgagePlanRevision
    components: dict[str, Decimal]
    rules: tuple[MortgageInstallmentRule, ...]


_STRATEGY_LABELS = {
    "minimum_only": "Minimum payments only",
    "snowball": "Snowball",
    "avalanche": "Avalanche",
    "custom": "Custom priority",
}
security_logger = logging.getLogger("security")


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
    scheduled_payment = terms.minimum_payment + terms.recurring_extra_payment
    plan = MortgagePaymentPlan.objects.filter(debt=debt).first()
    if plan is not None:
        revision = (
            plan.revisions.filter(effective_from__lte=on_date)
            .order_by("-effective_from", "-revision_number")
            .first()
        )
        if revision is not None:
            components = mortgage_components(revision)
            scheduled_payment = (
                revision.monthly_obligation + components["recurring_extra_principal"]
            )
    return DebtRow(
        debt=debt,
        terms=terms,
        scheduled_payment=scheduled_payment,
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
            security_logger.warning(
                "Debt account submission rejected.",
                extra={
                    "event": "debt.create_rejected",
                    "method": request.method,
                    "error_reference": _request_id(request),
                },
            )
            form.add_error(None, error)
        else:
            messages.success(request, "Debt account and initial terms added.")
            return redirect("debts:detail", debt_id=debt.pk)
    elif request.method == "POST":
        security_logger.warning(
            "Debt account submission rejected.",
            extra={
                "event": "debt.create_rejected",
                "method": request.method,
                "error_reference": _request_id(request),
            },
        )
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
    mortgage_plan = MortgagePaymentPlan.objects.filter(debt=debt).first()
    mortgage_rows: tuple[MortgageRevisionRow, ...] = ()
    current_mortgage: MortgageRevisionRow | None = None
    scheduled_payment = current_terms.minimum_payment + current_terms.recurring_extra_payment
    if mortgage_plan is not None:
        revisions = mortgage_plan.revisions.prefetch_related(
            "components", "installment_rules__source"
        ).order_by("-effective_from", "-revision_number")
        mortgage_rows = tuple(
            MortgageRevisionRow(
                revision=revision,
                components=mortgage_components(revision),
                rules=tuple(revision.installment_rules.all().order_by("installment_order")),
            )
            for revision in revisions
        )
        current_mortgage = next(
            (row for row in mortgage_rows if row.revision.effective_from <= _today(household)),
            None,
        )
        if current_mortgage is not None:
            scheduled_payment = (
                current_mortgage.revision.monthly_obligation
                + current_mortgage.components["recurring_extra_principal"]
            )
    return render(
        request,
        "debts/debt_detail.html",
        {
            "household": household,
            "debt": debt,
            "current_terms": current_terms,
            "scheduled_payment": scheduled_payment,
            "terms_revisions": terms,
            "statements": statements,
            "mortgage_plan": mortgage_plan,
            "mortgage_rows": mortgage_rows,
            "current_mortgage": current_mortgage,
            "current_nav": "debts",
        },
    )


def _mortgage_initial(revision: MortgagePlanRevision) -> dict[str, object]:
    components = mortgage_components(revision)
    rules = tuple(revision.installment_rules.order_by("installment_order"))
    if len(rules) != 2:
        raise Http404
    return {
        "monthly_obligation": revision.monthly_obligation,
        "principal_and_interest": components["principal_interest"],
        "escrow": components["escrow"],
        "pmi": components["pmi"],
        "fees": components["fees"],
        "recurring_extra_principal": components["recurring_extra_principal"],
        "statement_cycle_day": revision.statement_cycle_day,
        "installment_one_amount": rules[0].amount,
        "installment_one_day": rules[0].day_of_month,
        "installment_two_amount": rules[1].amount,
        "installment_two_day": rules[1].day_of_month,
        "adjustment_policy": rules[0].adjustment_policy,
    }


@login_required
@require_http_methods(("GET", "POST"))
def mortgage_plan_create(request: HttpRequest, debt_id: str) -> HttpResponse:
    household = get_active_household(request)
    debt = _debt(household, debt_id)
    if (
        debt.debt_type != DebtAccount.DebtType.MORTGAGE
        or MortgagePaymentPlan.objects.filter(debt=debt).exists()
    ):
        raise Http404
    form = MortgagePlanForm(
        request.POST or None,
        household=household,
        initial={"effective_from": _today(household)},
    )
    preview = None
    if request.method == "POST" and form.is_valid():
        try:
            spec = form.plan_spec()
            preview = preview_mortgage_plan(spec)
            if request.POST.get("action") == "confirm":
                create_mortgage_plan(
                    debt=debt,
                    actor=_actor(request),
                    spec=spec,
                    expected_preview_fingerprint=str(form.cleaned_data["preview_fingerprint"]),
                    request_id=_request_id(request),
                )
                messages.success(
                    request,
                    "Split mortgage plan saved and synced into paycheck periods.",
                )
                return redirect("debts:detail", debt_id=debt.pk)
            form.fields["preview_fingerprint"].initial = preview.fingerprint
        except ValidationError as error:
            form.add_error(None, error)
    return render(
        request,
        "debts/mortgage_plan_form.html",
        {
            "household": household,
            "debt": debt,
            "form": form,
            "preview": preview,
            "title": f"Set up {debt.name} payment plan",
            "current_nav": "debts",
        },
    )


@login_required
@require_http_methods(("GET", "POST"))
def mortgage_plan_revise(request: HttpRequest, debt_id: str) -> HttpResponse:
    household = get_active_household(request)
    debt = _debt(household, debt_id)
    plan = get_object_or_404(MortgagePaymentPlan, debt=debt)
    latest = (
        plan.revisions.prefetch_related("components", "installment_rules")
        .order_by("-revision_number")
        .first()
    )
    if latest is None:
        raise Http404
    initial = _mortgage_initial(latest)
    initial["effective_from"] = max(_today(household), latest.effective_from + timedelta(days=1))
    form = MortgagePlanForm(request.POST or None, household=household, initial=initial)
    preview = None
    if request.method == "POST" and form.is_valid():
        try:
            spec = form.plan_spec()
            preview = preview_mortgage_plan(spec, plan=plan)
            if request.POST.get("action") == "confirm":
                revise_mortgage_plan(
                    plan=plan,
                    actor=_actor(request),
                    spec=spec,
                    expected_preview_fingerprint=str(form.cleaned_data["preview_fingerprint"]),
                    request_id=_request_id(request),
                    reason=str(form.cleaned_data["reason"]),
                )
                messages.success(
                    request,
                    "Mortgage revision saved; prior schedule history remains protected.",
                )
                return redirect("debts:detail", debt_id=debt.pk)
            form.fields["preview_fingerprint"].initial = preview.fingerprint
        except ValidationError as error:
            form.add_error(None, error)
    return render(
        request,
        "debts/mortgage_plan_form.html",
        {
            "household": household,
            "debt": debt,
            "form": form,
            "preview": preview,
            "title": f"Revise {debt.name} payment plan",
            "is_revision": True,
            "current_nav": "debts",
        },
    )


@login_required
@require_http_methods(("GET", "POST"))
def mortgage_extra_principal(request: HttpRequest, occurrence_id: str) -> HttpResponse:
    household = get_active_household(request)
    occurrence = get_object_or_404(
        Occurrence.objects.select_related("source", "pay_period", "source__household").distinct(),
        pk=occurrence_id,
        source__household=household,
        source__mortgage_installment_rules__isnull=False,
    )
    current_extra = max(
        occurrence.planned_amount - occurrence.generated_amount,
        Decimal("0.00"),
    )
    form = ExtraPrincipalForm(
        request.POST or None,
        initial={"extra_principal": current_extra},
    )
    if request.method == "POST" and form.is_valid():
        try:
            set_one_off_extra_principal(
                occurrence=occurrence,
                actor=_actor(request),
                extra_principal=form.cleaned_data["extra_principal"],
                request_id=_request_id(request),
                reason=form.cleaned_data["reason"],
            )
        except ValidationError as error:
            form.add_error(None, error)
        else:
            messages.success(
                request,
                "One-off extra principal updated; future installments are unchanged.",
            )
            return redirect("budgets:detail", period_id=occurrence.pay_period_id)
    return render(
        request,
        "debts/mortgage_extra_principal.html",
        {
            "household": household,
            "occurrence": occurrence,
            "current_extra": current_extra,
            "form": form,
            "current_nav": "budget",
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
            security_logger.warning(
                "Debt account edit rejected.",
                extra={
                    "event": "debt.edit_rejected",
                    "method": request.method,
                    "error_reference": _request_id(request),
                },
            )
            form.add_error(None, error)
        else:
            messages.success(request, "Debt account details updated with protected audit history.")
            return redirect("debts:detail", debt_id=updated.pk)
    elif request.method == "POST":
        security_logger.warning(
            "Debt account edit rejected.",
            extra={
                "event": "debt.edit_rejected",
                "method": request.method,
                "error_reference": _request_id(request),
            },
        )
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
            security_logger.warning(
                "Debt terms submission rejected.",
                extra={
                    "event": "debt.terms_rejected",
                    "method": request.method,
                    "error_reference": _request_id(request),
                },
            )
            form.add_error(None, error)
        else:
            messages.success(request, f"Debt terms revision {revision.revision_number} added.")
            return redirect("debts:detail", debt_id=debt.pk)
    elif request.method == "POST":
        security_logger.warning(
            "Debt terms submission rejected.",
            extra={
                "event": "debt.terms_rejected",
                "method": request.method,
                "error_reference": _request_id(request),
            },
        )
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
            security_logger.warning(
                "Debt statement submission rejected.",
                extra={
                    "event": "debt.statement_rejected",
                    "method": request.method,
                    "error_reference": _request_id(request),
                },
            )
            form.add_error(None, error)
        else:
            messages.success(request, "Lender statement reconciled and protected.")
            return redirect("debts:detail", debt_id=debt.pk)
    elif request.method == "POST":
        security_logger.warning(
            "Debt statement submission rejected.",
            extra={
                "event": "debt.statement_rejected",
                "method": request.method,
                "error_reference": _request_id(request),
            },
        )
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
            security_logger.warning(
                "Debt statement correction rejected.",
                extra={
                    "event": "debt.statement_correction_rejected",
                    "method": request.method,
                    "error_reference": _request_id(request),
                },
            )
            form.add_error(None, error)
        else:
            messages.success(request, "Statement correction appended; the original was preserved.")
            return redirect("debts:detail", debt_id=debt.pk)
    elif request.method == "POST":
        security_logger.warning(
            "Debt statement correction rejected.",
            extra={
                "event": "debt.statement_correction_rejected",
                "method": request.method,
                "error_reference": _request_id(request),
            },
        )
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
            security_logger.warning(
                "Debt status change rejected.",
                extra={
                    "event": "debt.status_rejected",
                    "method": request.method,
                    "error_reference": _request_id(request),
                },
            )
            form.add_error(None, error)
        else:
            messages.success(request, f"Debt status changed to {updated.get_status_display()}.")
            return redirect("debts:detail", debt_id=updated.pk)
    elif request.method == "POST":
        security_logger.warning(
            "Debt status change rejected.",
            extra={
                "event": "debt.status_rejected",
                "method": request.method,
                "error_reference": _request_id(request),
            },
        )
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
