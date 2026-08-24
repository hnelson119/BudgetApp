from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation
from zoneinfo import ZoneInfo

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from audit.services import append_event
from debts.models import DebtAccount, DebtStatement, DebtTermsRevision
from households.models import Household
from households.services.access import require_household_membership
from identity.models import User
from ledger.models import FinancialAccount

_CENT = Decimal("0.01")
_RATE_UNIT = Decimal("0.0001")


@dataclass(frozen=True, slots=True)
class DebtTermsSpec:
    effective_from: date
    annual_percentage_rate: Decimal
    interest_method: str
    day_count_basis: str
    minimum_payment: Decimal
    recurring_extra_payment: Decimal = Decimal("0.00")
    due_day: int = 1
    custom_priority: int = 100
    projection_notes: str = ""


@dataclass(frozen=True, slots=True)
class DebtStatementSpec:
    statement_date: date
    statement_balance: Decimal
    annual_percentage_rate: Decimal
    minimum_payment: Decimal
    period_start: date | None = None
    period_end: date | None = None
    due_date: date | None = None
    principal_paid: Decimal = Decimal("0.00")
    interest_charged: Decimal = Decimal("0.00")
    fees_charged: Decimal = Decimal("0.00")
    escrow_paid: Decimal = Decimal("0.00")
    pmi_paid: Decimal = Decimal("0.00")
    extra_principal_paid: Decimal = Decimal("0.00")
    notes: str = ""


def _money(value: Decimal, label: str) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ValidationError(f"{label} must use a finite Decimal value.")
    try:
        normalized = value.quantize(_CENT)
    except InvalidOperation as error:
        raise ValidationError(f"{label} is invalid.") from error
    if normalized != value or normalized < 0:
        raise ValidationError(f"{label} must be nonnegative with at most two decimals.")
    return normalized


def _rate(value: Decimal) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ValidationError("APR must use a finite Decimal value.")
    try:
        normalized = value.quantize(_RATE_UNIT)
    except InvalidOperation as error:
        raise ValidationError("APR is invalid.") from error
    if normalized != value or not Decimal("0") <= normalized < Decimal("1000"):
        raise ValidationError("APR must be between 0 and 999.9999 percent.")
    return normalized


def _linked_liability(
    account: FinancialAccount | None,
    household: Household,
) -> FinancialAccount | None:
    if account is None:
        return None
    linked = FinancialAccount.objects.select_for_update().get(pk=account.pk)
    if linked.household_id != household.pk:
        raise ValidationError("The linked financial account belongs to another household.")
    if linked.archived_at is not None:
        raise ValidationError("Archived financial accounts cannot be linked to a new debt.")
    if linked.classification != FinancialAccount.Classification.LIABILITY:
        raise ValidationError("A debt must link to a liability account.")
    return linked


def _validated_terms(spec: DebtTermsSpec) -> DebtTermsSpec:
    if spec.interest_method not in DebtTermsRevision.InterestMethod.values:
        raise ValidationError("Debt interest method is invalid.")
    if spec.day_count_basis not in DebtTermsRevision.DayCountBasis.values:
        raise ValidationError("Debt day-count basis is invalid.")
    if not 1 <= spec.due_day <= 31:
        raise ValidationError("Debt due day must be between 1 and 31.")
    if spec.custom_priority < 1:
        raise ValidationError("Custom payoff priority must be positive.")
    if len(spec.projection_notes.strip()) > 500:
        raise ValidationError("Projection notes cannot exceed 500 characters.")
    return DebtTermsSpec(
        effective_from=spec.effective_from,
        annual_percentage_rate=_rate(spec.annual_percentage_rate),
        interest_method=spec.interest_method,
        day_count_basis=spec.day_count_basis,
        minimum_payment=_money(spec.minimum_payment, "Minimum payment"),
        recurring_extra_payment=_money(
            spec.recurring_extra_payment,
            "Recurring extra payment",
        ),
        due_day=spec.due_day,
        custom_priority=spec.custom_priority,
        projection_notes=spec.projection_notes.strip(),
    )


def _terms_payload(terms: DebtTermsRevision | DebtTermsSpec) -> dict[str, object]:
    return {
        "effective_from": terms.effective_from,
        "annual_percentage_rate": terms.annual_percentage_rate,
        "interest_method": terms.interest_method,
        "day_count_basis": terms.day_count_basis,
        "minimum_payment": terms.minimum_payment,
        "recurring_extra_payment": terms.recurring_extra_payment,
        "due_day": terms.due_day,
        "custom_priority": terms.custom_priority,
    }


def _create_terms_revision(
    *,
    debt: DebtAccount,
    actor: User,
    revision_number: int,
    spec: DebtTermsSpec,
) -> DebtTermsRevision:
    normalized = _validated_terms(spec)
    revision = DebtTermsRevision(
        debt=debt,
        revision_number=revision_number,
        effective_from=normalized.effective_from,
        annual_percentage_rate=normalized.annual_percentage_rate,
        interest_method=normalized.interest_method,
        day_count_basis=normalized.day_count_basis,
        minimum_payment=normalized.minimum_payment,
        recurring_extra_payment=normalized.recurring_extra_payment,
        due_day=normalized.due_day,
        custom_priority=normalized.custom_priority,
        projection_notes=normalized.projection_notes,
        created_by=actor,
    )
    revision.full_clean()
    revision._service_authorized = True  # type: ignore[attr-defined]
    revision.save()
    return revision


def current_debt_terms(debt: DebtAccount, *, on_date: date) -> DebtTermsRevision:
    terms = (
        DebtTermsRevision.objects.filter(debt=debt, effective_from__lte=on_date)
        .order_by("-effective_from", "-revision_number")
        .first()
    )
    if terms is None:
        raise ValidationError("The debt has no terms effective for the selected date.")
    return terms


@transaction.atomic
def create_debt_account(
    *,
    household: Household,
    actor: User,
    name: str,
    debt_type: str,
    opening_balance: Decimal,
    terms: DebtTermsSpec,
    request_id: str,
    financial_account: FinancialAccount | None = None,
    notes: str = "",
) -> tuple[DebtAccount, DebtTermsRevision]:
    require_household_membership(actor, household)
    if debt_type not in DebtAccount.DebtType.values:
        raise ValidationError("Debt type is invalid.")
    if terms.effective_from > timezone.localdate(timezone=ZoneInfo(household.time_zone)):
        raise ValidationError("Initial debt terms cannot begin in the future.")
    linked_account = _linked_liability(financial_account, household)
    debt = DebtAccount(
        household=household,
        financial_account=linked_account,
        name=name.strip(),
        debt_type=debt_type,
        current_balance=_money(opening_balance, "Opening balance"),
        status=DebtAccount.Status.ACTIVE,
        notes=notes.strip(),
        created_by=actor,
        updated_by=actor,
    )
    debt.full_clean()
    debt._service_authorized = True  # type: ignore[attr-defined]
    debt.save()
    revision = _create_terms_revision(debt=debt, actor=actor, revision_number=1, spec=terms)
    append_event(
        household=household,
        actor=actor,
        action="debt.account_created",
        entity_type="debt_account",
        entity_id=debt.pk,
        request_id=request_id,
        after={
            "name": debt.name,
            "debt_type": debt.debt_type,
            "opening_balance": debt.current_balance,
            "financial_account_id": debt.financial_account_id,
            "terms": _terms_payload(revision),
        },
    )
    return debt, revision


@transaction.atomic
def revise_debt_terms(
    *,
    debt: DebtAccount,
    actor: User,
    terms: DebtTermsSpec,
    request_id: str,
    reason: str,
) -> DebtTermsRevision:
    locked = DebtAccount.objects.select_for_update().select_related("household").get(pk=debt.pk)
    require_household_membership(actor, locked.household)
    if not locked.is_active:
        raise ValidationError("Only active debts can receive revised terms.")
    if not reason.strip():
        raise ValidationError("Revising debt terms requires a reason.")
    latest = (
        DebtTermsRevision.objects.select_for_update()
        .filter(debt=locked)
        .order_by("-revision_number")
        .first()
    )
    if latest is None:
        raise ValidationError("The debt is missing its initial terms.")
    if terms.effective_from <= latest.effective_from:
        raise ValidationError("Revised debt terms must begin after the latest revision.")
    revision = _create_terms_revision(
        debt=locked,
        actor=actor,
        revision_number=latest.revision_number + 1,
        spec=terms,
    )
    append_event(
        household=locked.household,
        actor=actor,
        action="debt.terms_revised",
        entity_type="debt_terms_revision",
        entity_id=revision.pk,
        request_id=request_id,
        before=_terms_payload(latest),
        after=_terms_payload(revision),
        reason=reason.strip(),
    )
    return revision


@transaction.atomic
def update_debt_account(
    *,
    debt: DebtAccount,
    actor: User,
    name: str,
    debt_type: str,
    financial_account: FinancialAccount | None,
    notes: str,
    request_id: str,
    reason: str,
) -> DebtAccount:
    locked = (
        DebtAccount.objects.select_for_update()
        .select_related("household", "financial_account")
        .get(pk=debt.pk)
    )
    require_household_membership(actor, locked.household)
    if debt_type not in DebtAccount.DebtType.values:
        raise ValidationError("Debt type is invalid.")
    if not reason.strip():
        raise ValidationError("Editing a debt account requires a reason.")
    before = {
        "name": locked.name,
        "debt_type": locked.debt_type,
        "financial_account_id": locked.financial_account_id,
        "notes": locked.notes,
    }
    locked.name = name.strip()
    locked.debt_type = debt_type
    locked.financial_account = _linked_liability(financial_account, locked.household)
    locked.notes = notes.strip()
    locked.updated_by = actor
    locked.full_clean()
    locked._service_authorized = True  # type: ignore[attr-defined]
    locked.save(
        update_fields=(
            "name",
            "debt_type",
            "financial_account",
            "notes",
            "updated_by",
            "updated_at",
        )
    )
    append_event(
        household=locked.household,
        actor=actor,
        action="debt.account_updated",
        entity_type="debt_account",
        entity_id=locked.pk,
        request_id=request_id,
        before=before,
        after={
            "name": locked.name,
            "debt_type": locked.debt_type,
            "financial_account_id": locked.financial_account_id,
            "notes": locked.notes,
        },
        reason=reason.strip(),
    )
    return locked


def _validated_statement(spec: DebtStatementSpec) -> DebtStatementSpec:
    return DebtStatementSpec(
        statement_date=spec.statement_date,
        statement_balance=_money(spec.statement_balance, "Statement balance"),
        annual_percentage_rate=_rate(spec.annual_percentage_rate),
        minimum_payment=_money(spec.minimum_payment, "Statement minimum payment"),
        period_start=spec.period_start,
        period_end=spec.period_end,
        due_date=spec.due_date,
        principal_paid=_money(spec.principal_paid, "Principal paid"),
        interest_charged=_money(spec.interest_charged, "Interest charged"),
        fees_charged=_money(spec.fees_charged, "Fees charged"),
        escrow_paid=_money(spec.escrow_paid, "Escrow paid"),
        pmi_paid=_money(spec.pmi_paid, "PMI paid"),
        extra_principal_paid=_money(spec.extra_principal_paid, "Extra principal paid"),
        notes=spec.notes.strip(),
    )


@transaction.atomic
def reconcile_debt_statement(
    *,
    debt: DebtAccount,
    actor: User,
    statement: DebtStatementSpec,
    request_id: str,
    supersedes: DebtStatement | None = None,
    reason: str = "",
) -> DebtStatement:
    locked = DebtAccount.objects.select_for_update().select_related("household").get(pk=debt.pk)
    require_household_membership(actor, locked.household)
    if locked.status == DebtAccount.Status.ARCHIVED:
        raise ValidationError("Archived debts cannot be reconciled.")
    normalized = _validated_statement(statement)
    if (
        supersedes is None
        and locked.last_reconciled_on
        and normalized.statement_date < locked.last_reconciled_on
    ):
        raise ValidationError("A statement cannot predate the latest reconciliation.")

    corrected: DebtStatement | None = None
    if supersedes is not None:
        if not reason.strip():
            raise ValidationError("Correcting a debt statement requires a reason.")
        corrected = (
            DebtStatement.objects.select_for_update().filter(pk=supersedes.pk, debt=locked).first()
        )
        if corrected is None:
            raise ValidationError("The corrected statement belongs to another debt.")
        if DebtStatement.objects.filter(supersedes=corrected).exists():
            raise ValidationError("The debt statement has already been corrected.")
        if normalized.statement_date != corrected.statement_date:
            raise ValidationError("A correction must use the original statement date.")
    elif DebtStatement.objects.filter(
        debt=locked,
        statement_date=normalized.statement_date,
        superseded_by__isnull=True,
    ).exists():
        raise ValidationError("That statement date is already reconciled; use a correction.")

    record = DebtStatement(
        debt=locked,
        supersedes=corrected,
        statement_date=normalized.statement_date,
        period_start=normalized.period_start,
        period_end=normalized.period_end,
        due_date=normalized.due_date,
        statement_balance=normalized.statement_balance,
        annual_percentage_rate=normalized.annual_percentage_rate,
        minimum_payment=normalized.minimum_payment,
        principal_paid=normalized.principal_paid,
        interest_charged=normalized.interest_charged,
        fees_charged=normalized.fees_charged,
        escrow_paid=normalized.escrow_paid,
        pmi_paid=normalized.pmi_paid,
        extra_principal_paid=normalized.extra_principal_paid,
        notes=normalized.notes,
        created_by=actor,
    )
    record.full_clean()
    record._service_authorized = True  # type: ignore[attr-defined]
    record.save()

    before_balance = locked.current_balance
    updates_current_balance = (
        locked.last_reconciled_on is None or normalized.statement_date >= locked.last_reconciled_on
    )
    if updates_current_balance:
        locked.current_balance = normalized.statement_balance
        locked.last_reconciled_on = normalized.statement_date
        locked.updated_by = actor
        if locked.current_balance == Decimal("0.00"):
            locked.status = DebtAccount.Status.PAID_OFF
            locked.status_changed_at = timezone.now()
        elif locked.status == DebtAccount.Status.PAID_OFF:
            locked.status = DebtAccount.Status.ACTIVE
            locked.status_changed_at = None
        locked.full_clean()
        locked._service_authorized = True  # type: ignore[attr-defined]
        locked.save(
            update_fields=(
                "current_balance",
                "last_reconciled_on",
                "status",
                "status_changed_at",
                "updated_by",
                "updated_at",
            )
        )
    append_event(
        household=locked.household,
        actor=actor,
        action=(
            "debt.statement_corrected" if corrected is not None else "debt.statement_reconciled"
        ),
        entity_type="debt_statement",
        entity_id=record.pk,
        request_id=request_id,
        before={
            "current_balance": before_balance,
            "superseded_statement_id": corrected.pk if corrected is not None else None,
        },
        after={
            "statement_date": record.statement_date,
            "statement_balance": record.statement_balance,
            "annual_percentage_rate": record.annual_percentage_rate,
            "minimum_payment": record.minimum_payment,
            "principal_paid": record.principal_paid,
            "interest_charged": record.interest_charged,
            "fees_charged": record.fees_charged,
            "escrow_paid": record.escrow_paid,
            "pmi_paid": record.pmi_paid,
            "extra_principal_paid": record.extra_principal_paid,
        },
        reason=reason.strip(),
    )
    return record


@transaction.atomic
def change_debt_status(
    *,
    debt: DebtAccount,
    actor: User,
    status: str,
    request_id: str,
    reason: str,
) -> DebtAccount:
    locked = DebtAccount.objects.select_for_update().select_related("household").get(pk=debt.pk)
    require_household_membership(actor, locked.household)
    if status not in DebtAccount.Status.values:
        raise ValidationError("Debt status is invalid.")
    if not reason.strip():
        raise ValidationError("Changing debt status requires a reason.")
    if status == DebtAccount.Status.PAID_OFF and locked.current_balance != Decimal("0.00"):
        raise ValidationError("Only a zero-balance debt can be marked paid off.")
    before_status = locked.status
    locked.status = status
    locked.status_changed_at = None if status == DebtAccount.Status.ACTIVE else timezone.now()
    locked.updated_by = actor
    locked.full_clean()
    locked._service_authorized = True  # type: ignore[attr-defined]
    locked.save(update_fields=("status", "status_changed_at", "updated_by", "updated_at"))
    append_event(
        household=locked.household,
        actor=actor,
        action="debt.status_changed",
        entity_type="debt_account",
        entity_id=locked.pk,
        request_id=request_id,
        before={"status": before_status},
        after={"status": locked.status},
        reason=reason.strip(),
    )
    return locked
