"""Monthly budget payments derived from debt terms, without posting ledger entries."""

from __future__ import annotations

from datetime import date, timedelta
from uuid import UUID
from zoneinfo import ZoneInfo

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from debts.models import DebtAccount, MortgagePlanRevision
from households.models import Household
from households.services.access import require_household_membership
from identity.models import User
from periods.models import PayPeriod
from schedules.models import RecurringSource, SourceRevision
from schedules.recurrence import BusinessDayAdjustment, Frequency, RecurrenceRule
from schedules.services.sources import (
    RevisionSpec,
    create_recurring_source,
    preview_revision,
    revise_recurring_source,
)


def is_debt_payment_revision(revision: SourceRevision) -> bool:
    return (
        revision.configuration.get("cash_flow_component")
        in ("debt_monthly_payment", "strategy_extra_payment")
        and revision.source.kind == RecurringSource.Kind.DEBT_PAYMENT
    )


def debt_payment_window(revision: SourceRevision) -> tuple[date, date]:
    debt = (
        DebtAccount.objects.filter(
            pk=revision.configuration["debt_account_id"], household_id=revision.source.household_id
        )
        .select_related("household")
        .first()
    )
    if debt is None:
        raise ValidationError("The debt payment schedule has no matching household debt.")
    today = timezone.localdate(timezone=ZoneInfo(debt.household.time_zone))
    if not debt.is_active or debt.current_balance == 0 or revision.expected_amount == 0:
        return today, today - timedelta(days=1)
    split = (
        MortgagePlanRevision.objects.filter(plan__debt=debt).order_by("effective_from").first()
        if revision.configuration.get("cash_flow_component") == "debt_monthly_payment"
        else None
    )
    return today, split.effective_from - timedelta(days=1) if split else date.max


@transaction.atomic
def synchronize_debt_payment(
    *, debt: DebtAccount, actor: User, request_id: str
) -> RecurringSource | None:
    """Ensure one source and one immutable schedule revision per debt terms revision."""
    require_household_membership(actor, debt.household)
    # Match occurrence generation's lock order and serialize the configuration-based link.
    Household.objects.select_for_update().get(pk=debt.household_id)
    locked = DebtAccount.objects.select_for_update().select_related("household").get(pk=debt.pk)
    source = (
        RecurringSource.objects.filter(
            household=locked.household,
            kind=RecurringSource.Kind.DEBT_PAYMENT,
            revisions__configuration__cash_flow_component="debt_monthly_payment",
            revisions__configuration__debt_account_id=str(locked.pk),
        )
        .distinct()
        .first()
    )
    if source is None and not locked.is_active:
        return None
    today = timezone.localdate(timezone=ZoneInfo(locked.household.time_zone))
    revisions = list(source.revisions.order_by("revision_number")) if source else []
    planned_from = revisions[0].start_date if revisions else today
    mapped_terms = {item.configuration["debt_terms_id"] for item in revisions}
    for terms in locked.terms_revisions.order_by("effective_from", "revision_number"):
        if str(terms.pk) in mapped_terms:
            continue
        spec = RevisionSpec(
            effective_from=terms.effective_from,
            expected_amount=terms.minimum_payment + terms.recurring_extra_payment,
            rule=RecurrenceRule(
                frequency=Frequency.MONTHLY_DAY,
                start_date=max(planned_from, terms.effective_from),
                day_of_month=terms.due_day,
            ),
            adjustment_policy=BusinessDayAdjustment.NONE,
            configuration={
                "cash_flow_component": "debt_monthly_payment",
                "debt_account_id": str(locked.pk),
                "debt_terms_id": str(terms.pk),
            },
        )
        preview = preview_revision(spec, preview_from=spec.effective_from)
        if source is None:
            name = locked.name
            if RecurringSource.objects.filter(
                household=locked.household,
                kind=RecurringSource.Kind.DEBT_PAYMENT,
                name__iexact=name,
            ).exists():
                name = f"{name[:99]} · payment {locked.pk.hex[:8]}"
            source, _ = create_recurring_source(
                household=locked.household,
                actor=actor,
                kind=RecurringSource.Kind.DEBT_PAYMENT,
                name=name,
                revision_spec=spec,
                expected_preview_fingerprint=preview.fingerprint,
                request_id=request_id,
                notes="Monthly payment from debt terms; minimum plus recurring extra payment.",
            )
        else:
            revise_recurring_source(
                source=source,
                actor=actor,
                revision_spec=spec,
                expected_preview_fingerprint=preview.fingerprint,
                request_id=request_id,
                reason="Synchronize revised debt terms with monthly budget payments.",
            )
    if source is not None:
        source_ids = tuple(
            RecurringSource.objects.filter(
                household=locked.household,
                kind=RecurringSource.Kind.DEBT_PAYMENT,
                revisions__configuration__debt_account_id=str(locked.pk),
                revisions__configuration__cash_flow_component__in=(
                    "debt_monthly_payment",
                    "strategy_extra_payment",
                ),
            )
            .values_list("pk", flat=True)
            .distinct()
        )
        synchronize_debt_periods(
            household=locked.household, actor=actor, source_ids=source_ids, request_id=request_id
        )
    return source


def synchronize_debt_periods(
    *, household: Household, actor: User, source_ids: tuple[UUID, ...], request_id: str
) -> None:
    from schedules.services.sync import synchronize_occurrences

    periods = PayPeriod.objects.filter(household=household).order_by("start_date")
    first, last = periods.first(), periods.last()
    if first is not None and last is not None:
        synchronize_occurrences(
            household=household,
            actor=actor,
            window_start=first.start_date,
            window_end=last.display_end_date,
            source_ids=source_ids,
            request_id=request_id,
        )
