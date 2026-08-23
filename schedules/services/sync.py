from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from decimal import Decimal

from django.core.exceptions import ValidationError
from django.db import transaction

from audit.services import append_event
from households.models import Household
from households.services.access import require_household_membership
from identity.models import User
from periods.models import PayPeriod
from schedules.models import Occurrence, RecurringSource, SourceRevision
from schedules.recurrence import BusinessDayAdjustment, project_occurrences
from schedules.services.sources import holidays_from_revision, rule_from_revision

_MAX_SYNC_DAYS = 366 * 5


@dataclass(frozen=True, slots=True)
class PlannedOccurrence:
    source: RecurringSource
    revision: SourceRevision
    nominal_date: date
    expected_date: date
    amount: Decimal
    pay_period: PayPeriod


@dataclass(frozen=True, slots=True)
class OccurrenceSyncResult:
    created_count: int
    refreshed_count: int
    superseded_count: int
    protected_count: int


def _containing_period(periods: list[PayPeriod], value: date) -> PayPeriod | None:
    return next((period for period in periods if period.contains(value)), None)


def _planned_occurrences(
    household: Household,
    *,
    window_start: date,
    window_end: date,
) -> tuple[PlannedOccurrence, ...]:
    periods = list(
        PayPeriod.objects.filter(
            household=household,
            start_date__lte=window_end,
            next_start_date__gt=window_start,
        ).order_by("start_date")
    )
    if not periods:
        raise ValidationError("Generate paycheck periods before generating occurrences.")
    sources = RecurringSource.objects.filter(household=household).prefetch_related("revisions")
    planned: list[PlannedOccurrence] = []
    for source in sources:
        revisions = list(source.revisions.order_by("effective_from", "revision_number"))
        for index, revision in enumerate(revisions):
            next_effective = (
                revisions[index + 1].effective_from if index + 1 < len(revisions) else None
            )
            effective_end = next_effective - timedelta(days=1) if next_effective else None
            if source.archived_from is not None:
                archive_end = source.archived_from - timedelta(days=1)
                effective_end = min(effective_end, archive_end) if effective_end else archive_end
            nominal_start = max(
                revision.effective_from,
                revision.start_date,
                window_start - timedelta(days=367),
            )
            nominal_end = window_end + timedelta(days=367)
            if effective_end is not None:
                nominal_end = min(nominal_end, effective_end)
            if nominal_end < nominal_start:
                continue
            projected = project_occurrences(
                rule_from_revision(revision),
                window_start=nominal_start,
                window_end=nominal_end,
                adjustment=BusinessDayAdjustment(revision.adjustment_policy),
                holidays=holidays_from_revision(revision),
            )
            for item in projected:
                if not window_start <= item.expected_date <= window_end:
                    continue
                pay_period = _containing_period(periods, item.expected_date)
                if pay_period is None:
                    raise ValidationError(
                        f"No paycheck period contains occurrence date {item.expected_date}."
                    )
                planned.append(
                    PlannedOccurrence(
                        source,
                        revision,
                        item.nominal_date,
                        item.expected_date,
                        revision.expected_amount,
                        pay_period,
                    )
                )
    return tuple(sorted(planned, key=lambda item: (item.expected_date, item.source.pk.hex)))


@transaction.atomic
def synchronize_occurrences(
    *,
    household: Household,
    actor: User,
    window_start: date,
    window_end: date,
    request_id: str,
) -> OccurrenceSyncResult:
    require_household_membership(actor, household)
    if window_end < window_start:
        raise ValidationError("Occurrence generation end cannot precede its start.")
    if (window_end - window_start).days > _MAX_SYNC_DAYS:
        raise ValidationError("An occurrence generation window cannot exceed five years.")
    Household.objects.select_for_update().get(pk=household.pk)
    planned = _planned_occurrences(
        household,
        window_start=window_start,
        window_end=window_end,
    )
    desired = {(item.revision.pk, item.nominal_date): item for item in planned}
    existing = list(
        Occurrence.objects.select_for_update(of=("self",))
        .filter(
            source__household=household,
            nominal_date__gte=window_start - timedelta(days=367),
            nominal_date__lte=window_end + timedelta(days=367),
        )
        .select_related("source_revision")
    )
    existing_by_key = {(item.source_revision_id, item.nominal_date): item for item in existing}
    created_count = 0
    refreshed_count = 0
    superseded_count = 0
    protected_count = 0

    for key, planned_item in desired.items():
        occurrence = existing_by_key.get(key)
        if occurrence is None:
            occurrence = Occurrence(
                source=planned_item.source,
                source_revision=planned_item.revision,
                nominal_date=planned_item.nominal_date,
                generated_expected_date=planned_item.expected_date,
                expected_date=planned_item.expected_date,
                generated_amount=planned_item.amount,
                planned_amount=planned_item.amount,
                pay_period=planned_item.pay_period,
            )
            occurrence.full_clean()
            occurrence.save()
            created_count += 1
        elif occurrence.status in (
            Occurrence.Status.SCHEDULED,
            Occurrence.Status.SUPERSEDED,
        ):
            occurrence.source = planned_item.source
            occurrence.generated_expected_date = planned_item.expected_date
            occurrence.expected_date = planned_item.expected_date
            occurrence.generated_amount = planned_item.amount
            occurrence.planned_amount = planned_item.amount
            occurrence.pay_period = planned_item.pay_period
            occurrence.status = Occurrence.Status.SCHEDULED
            occurrence.cancellation_reason = ""
            occurrence.cancelled_at = None
            occurrence.full_clean()
            occurrence.save(
                update_fields=(
                    "source",
                    "generated_expected_date",
                    "expected_date",
                    "generated_amount",
                    "planned_amount",
                    "pay_period",
                    "status",
                    "cancellation_reason",
                    "cancelled_at",
                    "updated_at",
                )
            )
            refreshed_count += 1
        else:
            protected_count += 1

    desired_keys = set(desired)
    for occurrence in existing:
        key = (occurrence.source_revision_id, occurrence.nominal_date)
        if key in desired_keys:
            continue
        if occurrence.status != Occurrence.Status.SCHEDULED:
            protected_count += 1
            continue
        occurrence.status = Occurrence.Status.SUPERSEDED
        occurrence.pay_period = None
        occurrence.save(update_fields=("status", "pay_period", "updated_at"))
        superseded_count += 1

    result = OccurrenceSyncResult(
        created_count,
        refreshed_count,
        superseded_count,
        protected_count,
    )
    append_event(
        household=household,
        actor=actor,
        action="schedule.occurrences_synchronized",
        entity_type="occurrence_window",
        entity_id=f"{window_start.isoformat()}_{window_end.isoformat()}",
        request_id=request_id,
        after={
            "window_start": window_start,
            "window_end": window_end,
            "created_count": result.created_count,
            "refreshed_count": result.refreshed_count,
            "superseded_count": result.superseded_count,
            "protected_count": result.protected_count,
        },
    )
    return result
