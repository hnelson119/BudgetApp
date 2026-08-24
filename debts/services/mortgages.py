from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation

from django.core.exceptions import ValidationError
from django.db import transaction

from audit.services import append_event
from debts.models import (
    DebtAccount,
    MortgageInstallmentRule,
    MortgagePaymentComponent,
    MortgagePaymentPlan,
    MortgagePlanRevision,
)
from households.services.access import require_household_membership
from identity.models import User
from periods.models import PayPeriod
from schedules.models import Occurrence, RecurringSource
from schedules.recurrence import BusinessDayAdjustment, Frequency, RecurrenceRule
from schedules.services import (
    OccurrenceSyncResult,
    RevisionPreview,
    RevisionSpec,
    create_recurring_source,
    override_occurrence,
    preview_revision,
    revise_recurring_source,
    synchronize_occurrences,
)

_CENT = Decimal("0.01")


@dataclass(frozen=True, slots=True)
class MortgageInstallmentSpec:
    amount: Decimal
    day_of_month: int


@dataclass(frozen=True, slots=True)
class MortgagePlanSpec:
    effective_from: date
    monthly_obligation: Decimal
    principal_and_interest: Decimal
    escrow: Decimal
    pmi: Decimal
    fees: Decimal
    recurring_extra_principal: Decimal
    statement_cycle_day: int
    installments: tuple[MortgageInstallmentSpec, MortgageInstallmentSpec]
    adjustment_policy: BusinessDayAdjustment = BusinessDayAdjustment.PREVIOUS


@dataclass(frozen=True, slots=True)
class MortgagePlanPreview:
    fingerprint: str
    installment_previews: tuple[RevisionPreview, RevisionPreview]


@dataclass(frozen=True, slots=True)
class MortgagePlanMutation:
    plan: MortgagePaymentPlan
    revision: MortgagePlanRevision
    occurrence_sync: OccurrenceSyncResult | None


def _money(value: Decimal, label: str, *, positive: bool = False) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ValidationError(f"{label} must use a finite Decimal value.")
    try:
        normalized = value.quantize(_CENT)
    except InvalidOperation as error:
        raise ValidationError(f"{label} is invalid.") from error
    if normalized != value or normalized < 0 or (positive and normalized == 0):
        requirement = "positive" if positive else "nonnegative"
        raise ValidationError(f"{label} must be {requirement} with at most two decimals.")
    return normalized


def _validated_spec(spec: MortgagePlanSpec) -> MortgagePlanSpec:
    try:
        policy = BusinessDayAdjustment(spec.adjustment_policy)
    except ValueError as error:
        raise ValidationError("Mortgage business-day adjustment policy is invalid.") from error
    if not 1 <= spec.statement_cycle_day <= 31:
        raise ValidationError("Mortgage statement-cycle day must be between 1 and 31.")
    if len(spec.installments) != 2:
        raise ValidationError("A split mortgage requires exactly two monthly installments.")
    first, second = spec.installments
    if not 1 <= first.day_of_month <= 31 or not 1 <= second.day_of_month <= 31:
        raise ValidationError("Mortgage installment days must be between 1 and 31.")
    if first.day_of_month >= second.day_of_month:
        raise ValidationError(
            "The first mortgage installment day must precede the second installment day."
        )
    monthly = _money(spec.monthly_obligation, "Monthly mortgage obligation", positive=True)
    principal_interest = _money(
        spec.principal_and_interest,
        "Mortgage principal and interest",
        positive=True,
    )
    escrow = _money(spec.escrow, "Mortgage escrow")
    pmi = _money(spec.pmi, "Mortgage PMI")
    fees = _money(spec.fees, "Mortgage fees")
    recurring_extra = _money(
        spec.recurring_extra_principal,
        "Recurring extra principal",
    )
    installment_one = _money(first.amount, "First mortgage installment", positive=True)
    installment_two = _money(second.amount, "Second mortgage installment", positive=True)
    if principal_interest + escrow + pmi + fees != monthly:
        raise ValidationError(
            "Principal and interest, escrow, PMI, and fees must total the monthly obligation."
        )
    scheduled_cash = monthly + recurring_extra
    if installment_one + installment_two != scheduled_cash:
        raise ValidationError(
            "The two mortgage installments must total the obligation plus recurring extra "
            "principal."
        )
    return MortgagePlanSpec(
        effective_from=spec.effective_from,
        monthly_obligation=monthly,
        principal_and_interest=principal_interest,
        escrow=escrow,
        pmi=pmi,
        fees=fees,
        recurring_extra_principal=recurring_extra,
        statement_cycle_day=spec.statement_cycle_day,
        installments=(
            MortgageInstallmentSpec(installment_one, first.day_of_month),
            MortgageInstallmentSpec(installment_two, second.day_of_month),
        ),
        adjustment_policy=policy,
    )


def _schedule_spec(
    spec: MortgagePlanSpec,
    *,
    plan_id: str,
    installment_order: int,
) -> RevisionSpec:
    installment = spec.installments[installment_order - 1]
    return RevisionSpec(
        effective_from=spec.effective_from,
        expected_amount=installment.amount,
        rule=RecurrenceRule(
            frequency=Frequency.MONTHLY_DAY,
            start_date=spec.effective_from,
            day_of_month=installment.day_of_month,
        ),
        adjustment_policy=spec.adjustment_policy,
        configuration={
            "mortgage_plan_id": plan_id,
            "installment_order": installment_order,
            "cash_flow_component": "mortgage_installment",
        },
    )


def _preview_for_plan_id(spec: MortgagePlanSpec, plan_id: str) -> MortgagePlanPreview:
    normalized = _validated_spec(spec)
    first_preview = preview_revision(
        _schedule_spec(normalized, plan_id=plan_id, installment_order=1),
        preview_from=normalized.effective_from,
    )
    second_preview = preview_revision(
        _schedule_spec(normalized, plan_id=plan_id, installment_order=2),
        preview_from=normalized.effective_from,
    )
    schedule_previews = (first_preview, second_preview)
    payload = {
        "effective_from": normalized.effective_from.isoformat(),
        "monthly_obligation": format(normalized.monthly_obligation, "f"),
        "principal_and_interest": format(normalized.principal_and_interest, "f"),
        "escrow": format(normalized.escrow, "f"),
        "pmi": format(normalized.pmi, "f"),
        "fees": format(normalized.fees, "f"),
        "recurring_extra_principal": format(
            normalized.recurring_extra_principal,
            "f",
        ),
        "statement_cycle_day": normalized.statement_cycle_day,
        "adjustment_policy": normalized.adjustment_policy.value,
        "installments": [
            {
                "amount": format(value.amount, "f"),
                "day_of_month": value.day_of_month,
                "schedule_fingerprint": schedule_previews[index].fingerprint,
            }
            for index, value in enumerate(normalized.installments)
        ],
    }
    fingerprint = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return MortgagePlanPreview(fingerprint, schedule_previews)


def preview_mortgage_plan(
    spec: MortgagePlanSpec,
    *,
    plan: MortgagePaymentPlan | None = None,
) -> MortgagePlanPreview:
    return _preview_for_plan_id(spec, str(plan.pk) if plan is not None else "new")


def mortgage_components(
    revision: MortgagePlanRevision,
) -> dict[str, Decimal]:
    components = {
        item.component_type: item.amount
        for item in revision.components.all().order_by("component_type")
    }
    expected = set(MortgagePaymentComponent.ComponentType.values)
    if set(components) != expected:
        raise ValidationError("The mortgage revision has incomplete payment components.")
    return components


def _create_plan_revision(
    *,
    plan: MortgagePaymentPlan,
    actor: User,
    revision_number: int,
    spec: MortgagePlanSpec,
    sources: tuple[RecurringSource, RecurringSource],
) -> MortgagePlanRevision:
    revision = MortgagePlanRevision(
        plan=plan,
        revision_number=revision_number,
        effective_from=spec.effective_from,
        monthly_obligation=spec.monthly_obligation,
        statement_cycle_day=spec.statement_cycle_day,
        created_by=actor,
    )
    revision.full_clean()
    revision._service_authorized = True  # type: ignore[attr-defined]
    revision.save()
    component_values = (
        (
            MortgagePaymentComponent.ComponentType.PRINCIPAL_INTEREST,
            spec.principal_and_interest,
        ),
        (MortgagePaymentComponent.ComponentType.ESCROW, spec.escrow),
        (MortgagePaymentComponent.ComponentType.PMI, spec.pmi),
        (MortgagePaymentComponent.ComponentType.FEES, spec.fees),
        (
            MortgagePaymentComponent.ComponentType.RECURRING_EXTRA_PRINCIPAL,
            spec.recurring_extra_principal,
        ),
    )
    for component_type, amount in component_values:
        component = MortgagePaymentComponent(
            plan_revision=revision,
            component_type=component_type,
            amount=amount,
            created_by=actor,
        )
        component.full_clean()
        component._service_authorized = True  # type: ignore[attr-defined]
        component.save()
    for order, (installment, source) in enumerate(
        zip(spec.installments, sources, strict=True),
        start=1,
    ):
        rule = MortgageInstallmentRule(
            plan_revision=revision,
            source=source,
            installment_order=order,
            amount=installment.amount,
            day_of_month=installment.day_of_month,
            adjustment_policy=spec.adjustment_policy.value,
            created_by=actor,
        )
        rule.full_clean()
        rule._service_authorized = True  # type: ignore[attr-defined]
        rule.save()
    return revision


def _sync_existing_periods(
    *,
    debt: DebtAccount,
    actor: User,
    request_id: str,
) -> OccurrenceSyncResult | None:
    periods = PayPeriod.objects.filter(household=debt.household).order_by("start_date")
    first = periods.first()
    last = periods.last()
    if first is None or last is None:
        return None
    return synchronize_occurrences(
        household=debt.household,
        actor=actor,
        window_start=first.start_date,
        window_end=last.display_end_date,
        request_id=request_id,
    )


def _plan_payload(
    revision: MortgagePlanRevision,
    components: dict[str, Decimal],
) -> dict[str, object]:
    rules = tuple(revision.installment_rules.order_by("installment_order"))
    return {
        "revision_number": revision.revision_number,
        "effective_from": revision.effective_from,
        "monthly_obligation": revision.monthly_obligation,
        "statement_cycle_day": revision.statement_cycle_day,
        "components": components,
        "installments": [
            {
                "order": rule.installment_order,
                "amount": rule.amount,
                "day_of_month": rule.day_of_month,
                "adjustment_policy": rule.adjustment_policy,
                "source_id": rule.source_id,
            }
            for rule in rules
        ],
    }


@transaction.atomic
def create_mortgage_plan(
    *,
    debt: DebtAccount,
    actor: User,
    spec: MortgagePlanSpec,
    expected_preview_fingerprint: str,
    request_id: str,
) -> MortgagePlanMutation:
    locked_debt = (
        DebtAccount.objects.select_for_update().select_related("household").get(pk=debt.pk)
    )
    require_household_membership(actor, locked_debt.household)
    if locked_debt.debt_type != DebtAccount.DebtType.MORTGAGE:
        raise ValidationError("Only mortgage debts can use a split-mortgage plan.")
    if not locked_debt.is_active:
        raise ValidationError("Only active mortgage debts can receive a payment plan.")
    if MortgagePaymentPlan.objects.filter(debt=locked_debt).exists():
        raise ValidationError("The mortgage debt already has a payment plan.")
    normalized = _validated_spec(spec)
    preview = _preview_for_plan_id(normalized, "new")
    if preview.fingerprint != expected_preview_fingerprint:
        raise ValidationError("The mortgage preview is stale; preview it again before saving.")
    plan = MortgagePaymentPlan(debt=locked_debt, created_by=actor)
    plan.full_clean()
    plan._service_authorized = True  # type: ignore[attr-defined]
    plan.save()
    sources: list[RecurringSource] = []
    for order in (1, 2):
        schedule_spec = _schedule_spec(
            normalized,
            plan_id=str(plan.pk),
            installment_order=order,
        )
        schedule_preview = preview_revision(
            schedule_spec,
            preview_from=normalized.effective_from,
        )
        source, _ = create_recurring_source(
            household=locked_debt.household,
            actor=actor,
            kind=RecurringSource.Kind.DEBT_PAYMENT,
            name=f"{locked_debt.name} · installment {order}",
            notes="Generated from the split-mortgage plan.",
            revision_spec=schedule_spec,
            expected_preview_fingerprint=schedule_preview.fingerprint,
            request_id=request_id,
        )
        sources.append(source)
    revision = _create_plan_revision(
        plan=plan,
        actor=actor,
        revision_number=1,
        spec=normalized,
        sources=(sources[0], sources[1]),
    )
    sync_result = _sync_existing_periods(
        debt=locked_debt,
        actor=actor,
        request_id=request_id,
    )
    components = mortgage_components(revision)
    append_event(
        household=locked_debt.household,
        actor=actor,
        action="mortgage.plan_created",
        entity_type="mortgage_payment_plan",
        entity_id=plan.pk,
        request_id=request_id,
        after=_plan_payload(revision, components),
    )
    return MortgagePlanMutation(plan, revision, sync_result)


@transaction.atomic
def revise_mortgage_plan(
    *,
    plan: MortgagePaymentPlan,
    actor: User,
    spec: MortgagePlanSpec,
    expected_preview_fingerprint: str,
    request_id: str,
    reason: str,
) -> MortgagePlanMutation:
    locked = (
        MortgagePaymentPlan.objects.select_for_update()
        .select_related("debt", "debt__household")
        .get(pk=plan.pk)
    )
    require_household_membership(actor, locked.debt.household)
    if not locked.debt.is_active:
        raise ValidationError("Only active mortgages can receive revised payment plans.")
    if not reason.strip():
        raise ValidationError("Revising a mortgage plan requires a reason.")
    latest = locked.revisions.order_by("-revision_number").first()
    if latest is None:
        raise ValidationError("The mortgage plan has no initial revision.")
    normalized = _validated_spec(spec)
    if normalized.effective_from <= latest.effective_from:
        raise ValidationError("A mortgage revision must begin after the latest revision.")
    preview = _preview_for_plan_id(normalized, str(locked.pk))
    if preview.fingerprint != expected_preview_fingerprint:
        raise ValidationError("The mortgage preview is stale; preview it again before saving.")
    latest_rules = tuple(
        latest.installment_rules.select_related("source").order_by("installment_order")
    )
    if len(latest_rules) != 2:
        raise ValidationError("The mortgage plan must have exactly two installment schedules.")
    sources = (latest_rules[0].source, latest_rules[1].source)
    before_components = mortgage_components(latest)
    for order, source in enumerate(sources, start=1):
        schedule_spec = _schedule_spec(
            normalized,
            plan_id=str(locked.pk),
            installment_order=order,
        )
        schedule_preview = preview_revision(
            schedule_spec,
            preview_from=normalized.effective_from,
        )
        revise_recurring_source(
            source=source,
            actor=actor,
            revision_spec=schedule_spec,
            expected_preview_fingerprint=schedule_preview.fingerprint,
            request_id=request_id,
            reason=reason,
        )
    revision = _create_plan_revision(
        plan=locked,
        actor=actor,
        revision_number=latest.revision_number + 1,
        spec=normalized,
        sources=sources,
    )
    sync_result = _sync_existing_periods(
        debt=locked.debt,
        actor=actor,
        request_id=request_id,
    )
    components = mortgage_components(revision)
    append_event(
        household=locked.debt.household,
        actor=actor,
        action="mortgage.plan_revised",
        entity_type="mortgage_plan_revision",
        entity_id=revision.pk,
        request_id=request_id,
        before=_plan_payload(latest, before_components),
        after=_plan_payload(revision, components),
        reason=reason.strip(),
    )
    return MortgagePlanMutation(locked, revision, sync_result)


@transaction.atomic
def set_one_off_extra_principal(
    *,
    occurrence: Occurrence,
    actor: User,
    extra_principal: Decimal,
    request_id: str,
    reason: str,
) -> Occurrence:
    locked = (
        Occurrence.objects.select_for_update()
        .select_related("source", "source__household", "pay_period")
        .get(pk=occurrence.pk)
    )
    require_household_membership(actor, locked.source.household)
    amount = _money(extra_principal, "One-off extra principal")
    if not reason.strip():
        raise ValidationError("Planning one-off extra principal requires a reason.")
    rule = (
        MortgageInstallmentRule.objects.filter(source=locked.source)
        .select_related("plan_revision__plan__debt")
        .order_by("-plan_revision__revision_number")
        .first()
    )
    if rule is None or rule.plan_revision.plan.debt.household_id != locked.source.household_id:
        raise ValidationError("The occurrence is not a mortgage installment.")
    before_amount = locked.planned_amount
    updated = override_occurrence(
        occurrence=locked,
        actor=actor,
        request_id=request_id,
        reason=f"One-off extra principal: {reason.strip()}",
        planned_amount=locked.generated_amount + amount,
    )
    append_event(
        household=locked.source.household,
        actor=actor,
        action="mortgage.extra_principal_planned",
        entity_type="occurrence",
        entity_id=locked.pk,
        request_id=request_id,
        before={"planned_amount": before_amount},
        after={
            "planned_amount": updated.planned_amount,
            "extra_principal": amount,
            "recurring_schedule_amount": locked.generated_amount,
        },
        reason=reason.strip(),
    )
    return updated
