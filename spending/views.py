from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, time
from decimal import Decimal
from typing import Any
from uuid import UUID
from zoneinfo import ZoneInfo

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.paginator import Paginator
from django.db.models import Exists, OuterRef, Q
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_GET, require_http_methods

from households.models import Household
from households.services.access import get_active_household
from identity.models import User
from ledger.models import FinancialAccount, JournalEntry, JournalPosting
from ledger.services import create_financial_account, record_expense, record_income, reverse_entry
from periods.models import PayPeriod
from spending.forms import (
    ExpenseForm,
    FinancialAccountForm,
    IncomeForm,
    ReversalForm,
    TransactionFilterForm,
)


@dataclass(frozen=True, slots=True)
class TransactionRow:
    entry: JournalEntry
    amount: Decimal
    accounts: str
    status: str
    can_reverse: bool
    local_effective_at: datetime


def _actor(request: HttpRequest) -> User:
    if not isinstance(request.user, User):
        raise PermissionDenied
    return request.user


def _request_id(request: HttpRequest) -> str:
    return str(request.request_id)  # type: ignore[attr-defined]


def _selected_period(request: HttpRequest, household: Household) -> PayPeriod | None:
    selected = request.GET.get("period", "").strip()
    if selected:
        try:
            selected_id = UUID(selected)
        except (TypeError, ValueError, AttributeError):
            selected_id = None
        if selected_id is not None:
            period = PayPeriod.objects.filter(household=household, pk=selected_id).first()
            if period is not None:
                return period
    today = timezone.localdate(timezone=ZoneInfo(household.time_zone))
    return (
        PayPeriod.objects.filter(
            household=household,
            start_date__lte=today,
            next_start_date__gt=today,
        ).first()
        or PayPeriod.objects.filter(household=household, start_date__gt=today).first()
        or PayPeriod.objects.filter(household=household).order_by("-start_date").first()
    )


def _period_context(household: Household, period: PayPeriod | None) -> dict[str, object]:
    if period is None:
        return {"period": None, "previous_period": None, "next_period": None}
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


def _entry_amount(entry: JournalEntry) -> Decimal:
    amount = sum(
        (
            posting.amount
            for posting in entry.postings.all()
            if posting.side == JournalPosting.Side.DEBIT
        ),
        Decimal("0.00"),
    )
    return -amount if entry.reversal_of_id is not None else amount


def _account_names(entry: JournalEntry) -> str:
    names = tuple(
        posting.financial_account.name
        for posting in entry.postings.all()
        if posting.financial_account is not None
    )
    return " → ".join(names) if names else "Internal ledger"


def _row(entry: JournalEntry, household: Household) -> TransactionRow:
    has_reversal = bool(getattr(entry, "has_reversal", False))
    if entry.reversal_of_id is not None:
        status = "Reversal"
    elif has_reversal:
        status = "Reversed"
    else:
        status = "Committed"
    return TransactionRow(
        entry=entry,
        amount=_entry_amount(entry),
        accounts=_account_names(entry),
        status=status,
        can_reverse=entry.reversal_of_id is None and not has_reversal,
        local_effective_at=timezone.localtime(
            entry.effective_at,
            ZoneInfo(household.time_zone),
        ),
    )


@login_required
@require_GET
def transaction_list(request: HttpRequest) -> HttpResponse:
    household = get_active_household(request)
    period = _selected_period(request, household)
    filter_form = TransactionFilterForm(request.GET or None, household=household)
    entries = (
        JournalEntry.objects.filter(household=household)
        .select_related("category", "created_by", "reversal_of")
        .prefetch_related("postings__financial_account")
        .annotate(has_reversal=Exists(JournalEntry.objects.filter(reversal_of_id=OuterRef("pk"))))
    )
    scope = request.GET.get("scope", "period")
    if scope != "all" and period is not None:
        zone = ZoneInfo(household.time_zone)
        start = datetime.combine(period.start_date, time.min, tzinfo=zone)
        end = datetime.combine(period.next_start_date, time.min, tzinfo=zone)
        entries = entries.filter(effective_at__gte=start, effective_at__lt=end)
        scope = "period"
    else:
        scope = "all"
    if filter_form.is_valid():
        query = str(filter_form.cleaned_data.get("q", "")).strip()
        entry_type = str(filter_form.cleaned_data.get("entry_type", ""))
        account = filter_form.cleaned_data.get("account")
        if query:
            entries = entries.filter(Q(description__icontains=query) | Q(note__icontains=query))
        if entry_type in JournalEntry.EntryType.values:
            entries = entries.filter(entry_type=entry_type)
        if isinstance(account, FinancialAccount):
            entries = entries.filter(postings__financial_account=account).distinct()
    paginator = Paginator(entries, 50)
    page = paginator.get_page(request.GET.get("page"))
    rows = tuple(_row(entry, household) for entry in page.object_list)
    page_query = request.GET.copy()
    page_query.pop("page", None)
    accounts = FinancialAccount.objects.filter(
        household=household,
        archived_at__isnull=True,
    ).order_by("name")
    context: dict[str, Any] = {
        "household": household,
        "rows": rows,
        "accounts": accounts,
        "filter_form": filter_form,
        "scope": scope,
        "page": page,
        "page_query": page_query.urlencode(),
        "current_nav": "spending",
        **_period_context(household, period),
    }
    return render(request, "spending/transaction_list.html", context)


@login_required
@require_http_methods(("GET", "POST"))
def expense_create(request: HttpRequest) -> HttpResponse:
    household = get_active_household(request)
    form = ExpenseForm(request.POST or None, household=household)
    if request.method == "POST" and form.is_valid():
        try:
            entry = record_expense(
                household=household,
                actor=_actor(request),
                account=form.cleaned_data["account"],
                category=form.cleaned_data["category"],
                amount=form.cleaned_data["amount"],
                effective_at=form.effective_at(),
                description=form.cleaned_data["description"],
                note=form.cleaned_data["note"],
                receipt_reference=form.cleaned_data["receipt_reference"],
                idempotency_key=form.idempotency_key(),
                request_id=_request_id(request),
            )
        except ValidationError as error:
            form.add_error(None, error)
        else:
            messages.success(request, "Expense recorded in the protected ledger.")
            return redirect("spending:transaction-detail", entry_id=entry.pk)
    return render(
        request,
        "spending/transaction_form.html",
        {
            "household": household,
            "form": form,
            "title": "Record expense",
            "eyebrow": "Manual transaction",
            "help_text": (
                "Card purchases count as spending now; the later card payment will not be "
                "counted again."
            ),
            "current_nav": "spending",
        },
    )


@login_required
@require_http_methods(("GET", "POST"))
def income_create(request: HttpRequest) -> HttpResponse:
    household = get_active_household(request)
    form = IncomeForm(request.POST or None, household=household)
    if request.method == "POST" and form.is_valid():
        try:
            entry = record_income(
                household=household,
                actor=_actor(request),
                destination=form.cleaned_data["destination"],
                amount=form.cleaned_data["amount"],
                effective_at=form.effective_at(),
                description=form.cleaned_data["description"],
                note=form.cleaned_data["note"],
                idempotency_key=form.idempotency_key(),
                request_id=_request_id(request),
            )
        except ValidationError as error:
            form.add_error(None, error)
        else:
            messages.success(request, "Income recorded in the protected ledger.")
            return redirect("spending:transaction-detail", entry_id=entry.pk)
    return render(
        request,
        "spending/transaction_form.html",
        {
            "household": household,
            "form": form,
            "title": "Record income",
            "eyebrow": "Manual transaction",
            "help_text": (
                "This records actual income without changing the source schedule or future "
                "paycheck periods."
            ),
            "current_nav": "spending",
        },
    )


@login_required
@require_http_methods(("GET", "POST"))
def account_create(request: HttpRequest) -> HttpResponse:
    household = get_active_household(request)
    form = FinancialAccountForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        account_type, classification = form.account_type_and_classification()
        try:
            create_financial_account(
                household=household,
                actor=_actor(request),
                name=form.cleaned_data["name"],
                account_type=account_type,
                classification=classification,
                last_four=form.cleaned_data["last_four"],
                notes=form.cleaned_data["notes"],
                request_id=_request_id(request),
            )
        except ValidationError as error:
            form.add_error(None, error)
        else:
            messages.success(request, "Financial account added.")
            return redirect("spending:transaction-list")
    return render(
        request,
        "spending/transaction_form.html",
        {
            "household": household,
            "form": form,
            "title": "Add financial account",
            "eyebrow": "Account setup",
            "help_text": (
                "Store only a nickname and optional last four digits—never a full account or "
                "card number."
            ),
            "current_nav": "spending",
        },
    )


@login_required
@require_GET
def transaction_detail(request: HttpRequest, entry_id: str) -> HttpResponse:
    household = get_active_household(request)
    entry = get_object_or_404(
        JournalEntry.objects.filter(household=household)
        .select_related("category", "created_by", "reversal_of")
        .prefetch_related("postings__financial_account")
        .annotate(has_reversal=Exists(JournalEntry.objects.filter(reversal_of_id=OuterRef("pk")))),
        pk=entry_id,
    )
    reversal = JournalEntry.objects.filter(reversal_of=entry).first()
    return render(
        request,
        "spending/transaction_detail.html",
        {
            "household": household,
            "row": _row(entry, household),
            "postings": entry.postings.all(),
            "reversal": reversal,
            "current_nav": "spending",
        },
    )


@login_required
@require_http_methods(("GET", "POST"))
def transaction_reverse(request: HttpRequest, entry_id: str) -> HttpResponse:
    household = get_active_household(request)
    entry = get_object_or_404(
        JournalEntry.objects.filter(household=household)
        .prefetch_related("postings__financial_account")
        .annotate(has_reversal=Exists(JournalEntry.objects.filter(reversal_of_id=OuterRef("pk")))),
        pk=entry_id,
    )
    row = _row(entry, household)
    if not row.can_reverse:
        raise Http404("This transaction cannot be reversed again.")
    form = ReversalForm(request.POST or None, household=household)
    if request.method == "POST" and form.is_valid():
        try:
            reversal = reverse_entry(
                entry=entry,
                actor=_actor(request),
                effective_at=form.effective_at(),
                request_id=_request_id(request),
                reason=form.cleaned_data["reason"],
            )
        except ValidationError as error:
            form.add_error(None, error)
        else:
            messages.success(
                request,
                "Full refund/reversal recorded; the original remains visible.",
            )
            return redirect("spending:transaction-detail", entry_id=reversal.pk)
    return render(
        request,
        "spending/transaction_reverse.html",
        {
            "household": household,
            "row": row,
            "form": form,
            "current_nav": "spending",
        },
    )
