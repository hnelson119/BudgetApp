from __future__ import annotations

import hashlib
import itertools
import json
import uuid
from dataclasses import dataclass
from datetime import date, timedelta

from django.core.exceptions import ValidationError
from django.db import models, transaction

from audit.services import append_event
from households.models import Household
from households.services.access import require_household_membership
from identity.models import User
from periods.models import PayPeriod
from schedules.models import Occurrence, RecurringSource, SourceRevision
from schedules.recurrence import BusinessDayAdjustment, project_occurrences
from schedules.services.sources import holidays_from_revision, rule_from_revision

_MAX_SYNC_DAYS = 366 * 5
_ANCHOR_SEARCH_DAYS = 366 * 10


@dataclass(frozen=True, slots=True)
class PeriodRange:
    start_date: date
    next_start_date: date


@dataclass(frozen=True, slots=True)
class PeriodResize:
    period_id: uuid.UUID
    start_date: date
    old_next_start_date: date
    new_next_start_date: date


@dataclass(frozen=True, slots=True)
class PeriodSyncPreview:
    desired_ranges: tuple[PeriodRange, ...]
    create_ranges: tuple[PeriodRange, ...]
    resize_periods: tuple[PeriodResize, ...]
    remove_period_ids: tuple[uuid.UUID, ...]
    conflicts: tuple[str, ...]
    fingerprint: str


def period_ranges(anchor_dates: tuple[date, ...]) -> tuple[PeriodRange, ...]:
    distinct_dates = sorted(set(anchor_dates))
    return tuple(
        PeriodRange(start_date=start, next_start_date=end)
        for start, end in itertools.pairwise(distinct_dates)
        if end > start
    )


def _revision_effective_end(revisions: list[SourceRevision], index: int) -> date | None:
    if index + 1 >= len(revisions):
        return None
    return revisions[index + 1].effective_from - timedelta(days=1)


def _anchor_dates(
    household: Household,
    *,
    search_start: date,
    search_end: date,
) -> tuple[date, ...]:
    sources = (
        RecurringSource.objects.filter(
            household=household,
            kind=RecurringSource.Kind.INCOME,
            income_detail__starts_budget_period=True,
        )
        .prefetch_related("revisions")
        .order_by("id")
    )
    anchors: set[date] = set()
    for source in sources:
        revisions = list(source.revisions.order_by("effective_from", "revision_number"))
        for index, revision in enumerate(revisions):
            effective_end = _revision_effective_end(revisions, index)
            if source.archived_from is not None:
                archive_end = source.archived_from - timedelta(days=1)
                effective_end = min(effective_end, archive_end) if effective_end else archive_end
            nominal_start = max(search_start - timedelta(days=367), revision.effective_from)
            nominal_end = search_end + timedelta(days=367)
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
            anchors.update(
                item.expected_date
                for item in projected
                if search_start <= item.expected_date <= search_end
            )
    return tuple(sorted(anchors))


def _desired_ranges(
    household: Household,
    *,
    window_start: date,
    window_end: date,
) -> tuple[PeriodRange, ...]:
    if window_end < window_start:
        raise ValidationError("Period generation end cannot precede its start.")
    if (window_end - window_start).days > _MAX_SYNC_DAYS:
        raise ValidationError("A period generation window cannot exceed five years.")
    anchors = _anchor_dates(
        household,
        search_start=window_start - timedelta(days=_ANCHOR_SEARCH_DAYS),
        search_end=window_end + timedelta(days=_ANCHOR_SEARCH_DAYS),
    )
    actual_boundaries = Occurrence.objects.filter(
        source__household=household,
        source__kind=RecurringSource.Kind.INCOME,
        source__income_detail__starts_budget_period=True,
        status__in=(Occurrence.Status.COMPLETED, Occurrence.Status.CORRECTED),
        actual_date__isnull=False,
        pay_period__boundary_source=PayPeriod.BoundarySource.ACTUAL,
        pay_period__start_date=models.F("actual_date"),
    ).values_list("generated_expected_date", "actual_date")
    replacements = {
        expected: actual for expected, actual in actual_boundaries if actual is not None
    }
    anchors = tuple(sorted({replacements.get(anchor, anchor) for anchor in anchors}))
    if len(anchors) < 2:
        raise ValidationError("At least two distinct anchor dates are required to form a period.")
    starts_on_or_before = [value for value in anchors if value <= window_start]
    first_start = starts_on_or_before[-1] if starts_on_or_before else anchors[0]
    after_window = [value for value in anchors if value > window_end]
    if not after_window:
        raise ValidationError("An anchor after the generation window is required.")
    final_boundary = after_window[0]
    selected = tuple(value for value in anchors if first_start <= value <= final_boundary)
    return period_ranges(selected)


def _preview_payload(
    household: Household,
    *,
    window_start: date,
    window_end: date,
    desired: tuple[PeriodRange, ...],
    create: tuple[PeriodRange, ...],
    resize: tuple[PeriodResize, ...],
    remove: tuple[uuid.UUID, ...],
    conflicts: tuple[str, ...],
) -> dict[str, object]:
    return {
        "household_id": str(household.pk),
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "desired": [
            [item.start_date.isoformat(), item.next_start_date.isoformat()] for item in desired
        ],
        "create": [
            [item.start_date.isoformat(), item.next_start_date.isoformat()] for item in create
        ],
        "resize": [
            [
                str(item.period_id),
                item.start_date.isoformat(),
                item.old_next_start_date.isoformat(),
                item.new_next_start_date.isoformat(),
            ]
            for item in resize
        ],
        "remove": [str(item) for item in remove],
        "conflicts": list(conflicts),
    }


def preview_period_sync(
    *,
    household: Household,
    window_start: date,
    window_end: date,
) -> PeriodSyncPreview:
    desired = _desired_ranges(household, window_start=window_start, window_end=window_end)
    desired_by_start = {item.start_date: item for item in desired}
    managed_start = desired[0].start_date
    managed_end = desired[-1].next_start_date
    existing = list(
        PayPeriod.objects.filter(
            household=household,
            start_date__lt=managed_end,
            next_start_date__gt=managed_start,
        ).order_by("start_date")
    )
    existing_by_start = {item.start_date: item for item in existing}
    create = tuple(item for item in desired if item.start_date not in existing_by_start)
    resize: list[PeriodResize] = []
    remove: list[uuid.UUID] = []
    conflicts: list[str] = []

    for period in existing:
        wanted = desired_by_start.get(period.start_date)
        if wanted is None:
            protected_count = period.occurrences.exclude(status=Occurrence.Status.SCHEDULED).count()
            if period.status != PayPeriod.Status.PROJECTED or protected_count:
                conflicts.append(
                    f"Period {period.start_date.isoformat()} has protected state or occurrences."
                )
            else:
                remove.append(period.pk)
        elif wanted.next_start_date != period.next_start_date:
            if period.status != PayPeriod.Status.PROJECTED:
                conflicts.append(
                    f"Period {period.start_date.isoformat()} is not projected and cannot resize."
                )
            else:
                resize.append(
                    PeriodResize(
                        period.pk,
                        period.start_date,
                        period.next_start_date,
                        wanted.next_start_date,
                    )
                )

    payload = _preview_payload(
        household,
        window_start=window_start,
        window_end=window_end,
        desired=desired,
        create=create,
        resize=tuple(resize),
        remove=tuple(remove),
        conflicts=tuple(conflicts),
    )
    fingerprint = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return PeriodSyncPreview(
        desired,
        create,
        tuple(resize),
        tuple(remove),
        tuple(conflicts),
        fingerprint,
    )


@transaction.atomic
def apply_period_sync(
    *,
    household: Household,
    actor: User,
    window_start: date,
    window_end: date,
    expected_preview_fingerprint: str,
    request_id: str,
) -> PeriodSyncPreview:
    require_household_membership(actor, household)
    Household.objects.select_for_update().get(pk=household.pk)
    preview = preview_period_sync(
        household=household,
        window_start=window_start,
        window_end=window_end,
    )
    if preview.fingerprint != expected_preview_fingerprint:
        raise ValidationError("The period preview is stale; preview it again before applying.")
    if preview.conflicts:
        raise ValidationError({"periods": list(preview.conflicts)})

    for period_id in preview.remove_period_ids:
        period = PayPeriod.objects.select_for_update().get(pk=period_id)
        period.occurrences.filter(status=Occurrence.Status.SCHEDULED).update(
            pay_period=None,
            status=Occurrence.Status.SUPERSEDED,
        )
        period.delete()
    for resize in preview.resize_periods:
        period = PayPeriod.objects.select_for_update().get(pk=resize.period_id)
        period.next_start_date = resize.new_next_start_date
        period.boundary_revision += 1
        period.full_clean()
        period.save(update_fields=("next_start_date", "boundary_revision", "updated_at"))
    for period_range in preview.create_ranges:
        period = PayPeriod(
            household=household,
            start_date=period_range.start_date,
            next_start_date=period_range.next_start_date,
            created_by=actor,
        )
        period.full_clean()
        period.save()

    append_event(
        household=household,
        actor=actor,
        action="periods.projection_synchronized",
        entity_type="pay_period_window",
        entity_id=preview.fingerprint[:32],
        request_id=request_id,
        after={
            "window_start": window_start,
            "window_end": window_end,
            "created_count": len(preview.create_ranges),
            "resized_count": len(preview.resize_periods),
            "removed_count": len(preview.remove_period_ids),
        },
    )
    return preview
