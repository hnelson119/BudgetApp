from __future__ import annotations

import itertools
import random
from dataclasses import dataclass
from datetime import date, timedelta
from decimal import Decimal
from unittest.mock import patch

import pytest
from django.core.exceptions import PermissionDenied, ValidationError

from audit.models import AuditEvent
from households.models import Household, HouseholdMembership
from identity.models import User
from periods.models import PayPeriod, PayPeriodClosingRevision
from periods.services import (
    apply_period_sync,
    close_period,
    period_ranges,
    preview_boundary_change,
    preview_period_sync,
    refresh_period_states,
    reopen_period,
)
from reserves.models import ReserveEntry
from reserves.services import reserve_balance
from schedules.models import Occurrence, RecurringSource, SourceRevision
from schedules.recurrence import (
    BusinessDayAdjustment,
    Frequency,
    RecurrenceRule,
    occurrences_between,
    project_occurrences,
)
from schedules.services import (
    RevisionSpec,
    cancel_occurrence_and_future,
    complete_occurrence,
    create_recurring_source,
    move_occurrence,
    override_occurrence,
    preview_revision,
    revise_recurring_source,
    synchronize_occurrences,
)

TEST_PASSWORD = "correct-horse-battery-test"  # pragma: allowlist secret


@dataclass(frozen=True)
class ScheduleContext:
    household: Household
    user: User
    outsider: User


@pytest.fixture
def schedule_context(db: object) -> ScheduleContext:
    household = Household.objects.create(name="Nelson Household")
    user = User.objects.create_user(email="member@example.com", password=TEST_PASSWORD)
    outsider = User.objects.create_user(email="outsider@example.com", password=TEST_PASSWORD)
    HouseholdMembership.objects.create(household=household, user=user)
    return ScheduleContext(household, user, outsider)


def create_source(
    context: ScheduleContext,
    *,
    name: str,
    rule: RecurrenceRule,
    kind: str = RecurringSource.Kind.FIXED_EXPENSE,
    amount: Decimal = Decimal("100.00"),
    effective_from: date | None = None,
    starts_budget_period: bool = False,
    adjustment: BusinessDayAdjustment = BusinessDayAdjustment.NONE,
    holiday_dates: tuple[date, ...] = (),
) -> tuple[RecurringSource, SourceRevision]:
    specification = RevisionSpec(
        effective_from=effective_from or rule.start_date,
        expected_amount=amount,
        rule=rule,
        adjustment_policy=adjustment,
        holiday_dates=holiday_dates,
    )
    preview = preview_revision(specification, preview_from=specification.effective_from)
    return create_recurring_source(
        household=context.household,
        actor=context.user,
        kind=kind,
        name=name,
        revision_spec=specification,
        expected_preview_fingerprint=preview.fingerprint,
        request_id=f"request-create-{name.lower().replace(' ', '-')}",
        starts_budget_period=starts_budget_period,
    )


def create_weekly_anchor(
    context: ScheduleContext,
    *,
    name: str = "Primary paycheck",
    start: date = date(2026, 8, 20),
    weekday: int = 3,
) -> tuple[RecurringSource, SourceRevision]:
    return create_source(
        context,
        name=name,
        kind=RecurringSource.Kind.INCOME,
        amount=Decimal("1500.00"),
        starts_budget_period=True,
        rule=RecurrenceRule(
            frequency=Frequency.WEEKLY,
            start_date=start,
            weekdays=(weekday,),
        ),
    )


def generate_periods(
    context: ScheduleContext,
    *,
    window_start: date = date(2026, 8, 20),
    window_end: date = date(2026, 9, 10),
) -> None:
    preview = preview_period_sync(
        household=context.household,
        window_start=window_start,
        window_end=window_end,
    )
    apply_period_sync(
        household=context.household,
        actor=context.user,
        window_start=window_start,
        window_end=window_end,
        expected_preview_fingerprint=preview.fingerprint,
        request_id="request-period-sync",
    )


@pytest.mark.parametrize(
    ("rule", "window_end", "expected"),
    [
        (
            RecurrenceRule(Frequency.ONCE, date(2026, 1, 15)),
            date(2026, 12, 31),
            (date(2026, 1, 15),),
        ),
        (
            RecurrenceRule(Frequency.DAILY, date(2026, 1, 1), interval=3),
            date(2026, 1, 10),
            tuple(date(2026, 1, day) for day in (1, 4, 7, 10)),
        ),
        (
            RecurrenceRule(
                Frequency.WEEKLY,
                date(2026, 8, 19),
                interval=2,
                weekdays=(2, 3),
            ),
            date(2026, 9, 3),
            tuple(
                date.fromisoformat(value)
                for value in ("2026-08-19", "2026-08-20", "2026-09-02", "2026-09-03")
            ),
        ),
        (
            RecurrenceRule(
                Frequency.MONTHLY_DAY,
                date(2026, 1, 31),
                interval=3,
                day_of_month=31,
            ),
            date(2026, 10, 31),
            tuple(
                date.fromisoformat(value)
                for value in ("2026-01-31", "2026-04-30", "2026-07-31", "2026-10-31")
            ),
        ),
        (
            RecurrenceRule(
                Frequency.MONTHLY_NTH_WEEKDAY,
                date(2026, 1, 1),
                weekday=2,
                ordinal=2,
            ),
            date(2026, 3, 31),
            tuple(
                date.fromisoformat(value) for value in ("2026-01-14", "2026-02-11", "2026-03-11")
            ),
        ),
        (
            RecurrenceRule(
                Frequency.MONTHLY_LAST_WEEKDAY,
                date(2026, 1, 1),
                weekday=4,
            ),
            date(2026, 3, 31),
            tuple(
                date.fromisoformat(value) for value in ("2026-01-30", "2026-02-27", "2026-03-27")
            ),
        ),
        (
            RecurrenceRule(
                Frequency.ANNUAL,
                date(2024, 2, 29),
                day_of_month=29,
                month_of_year=2,
            ),
            date(2028, 3, 1),
            tuple(
                date.fromisoformat(value)
                for value in ("2024-02-29", "2025-02-28", "2026-02-28", "2027-02-28", "2028-02-29")
            ),
        ),
    ],
)
def test_recurrence_patterns_are_deterministic(
    rule: RecurrenceRule,
    window_end: date,
    expected: tuple[date, ...],
) -> None:
    assert (
        occurrences_between(
            rule,
            window_start=rule.start_date,
            window_end=window_end,
        )
        == expected
    )


def test_recurrence_skips_missing_fifth_weekday_and_adjusts_business_days() -> None:
    fifth_monday = RecurrenceRule(
        Frequency.MONTHLY_NTH_WEEKDAY,
        date(2026, 1, 1),
        weekday=0,
        ordinal=5,
    )
    assert occurrences_between(
        fifth_monday,
        window_start=date(2026, 1, 1),
        window_end=date(2026, 3, 31),
    ) == (date(2026, 3, 30),)

    saturday = RecurrenceRule(Frequency.ONCE, date(2026, 7, 4))
    projected = project_occurrences(
        saturday,
        window_start=date(2026, 7, 1),
        window_end=date(2026, 7, 7),
        adjustment=BusinessDayAdjustment.PREVIOUS,
        holidays=frozenset({date(2026, 7, 3)}),
    )
    assert projected[0].nominal_date == date(2026, 7, 4)
    assert projected[0].expected_date == date(2026, 7, 2)


def test_randomized_period_ranges_are_half_open_and_never_overlap() -> None:
    generator = random.Random(4104)
    for _ in range(100):
        cursor = date(2026, 1, 1)
        anchors = [cursor]
        for _ in range(generator.randint(2, 30)):
            cursor += timedelta(days=generator.randint(1, 35))
            anchors.append(cursor)
            if generator.random() < 0.2:
                anchors.append(cursor)
        ranges = period_ranges(tuple(anchors))
        assert all(item.start_date < item.next_start_date for item in ranges)
        assert all(
            left.next_start_date == right.start_date for left, right in itertools.pairwise(ranges)
        )


@pytest.mark.django_db
def test_paycheck_boundaries_drive_periods_and_due_date_assignment(
    schedule_context: ScheduleContext,
) -> None:
    create_weekly_anchor(schedule_context)
    create_source(
        schedule_context,
        name="Bill due Wednesday",
        rule=RecurrenceRule(Frequency.ONCE, date(2026, 8, 26)),
    )
    create_source(
        schedule_context,
        name="Bill due Thursday",
        rule=RecurrenceRule(Frequency.ONCE, date(2026, 8, 27)),
    )
    create_source(
        schedule_context,
        name="One-time bonus",
        kind=RecurringSource.Kind.INCOME,
        amount=Decimal("250.00"),
        rule=RecurrenceRule(Frequency.ONCE, date(2026, 8, 25)),
        starts_budget_period=False,
    )
    generate_periods(schedule_context)
    synchronize_occurrences(
        household=schedule_context.household,
        actor=schedule_context.user,
        window_start=date(2026, 8, 20),
        window_end=date(2026, 9, 10),
        request_id="request-occurrence-sync",
    )

    first = PayPeriod.objects.get(
        household=schedule_context.household,
        start_date=date(2026, 8, 20),
    )
    second = PayPeriod.objects.get(
        household=schedule_context.household,
        start_date=date(2026, 8, 27),
    )
    assert first.next_start_date == date(2026, 8, 27)
    assert first.display_end_date == date(2026, 8, 26)
    assert Occurrence.objects.get(source__name="Bill due Wednesday").pay_period == first
    assert Occurrence.objects.get(source__name="Bill due Thursday").pay_period == second
    assert Occurrence.objects.get(source__name="One-time bonus").pay_period == first
    assert not PayPeriod.objects.filter(start_date=date(2026, 8, 25)).exists()


@pytest.mark.django_db
def test_same_day_income_anchors_deduplicate_and_stale_previews_fail(
    schedule_context: ScheduleContext,
) -> None:
    create_weekly_anchor(schedule_context, name="Paycheck A")
    create_weekly_anchor(schedule_context, name="Paycheck B")
    preview = preview_period_sync(
        household=schedule_context.household,
        window_start=date(2026, 8, 20),
        window_end=date(2026, 9, 3),
    )
    assert [item.start_date for item in preview.desired_ranges] == [
        date(2026, 8, 20),
        date(2026, 8, 27),
        date(2026, 9, 3),
    ]

    create_weekly_anchor(
        schedule_context,
        name="Tuesday paycheck",
        start=date(2026, 8, 25),
        weekday=1,
    )
    with pytest.raises(ValidationError, match="preview is stale"):
        apply_period_sync(
            household=schedule_context.household,
            actor=schedule_context.user,
            window_start=date(2026, 8, 20),
            window_end=date(2026, 9, 3),
            expected_preview_fingerprint=preview.fingerprint,
            request_id="request-stale-period-preview",
        )
    assert PayPeriod.objects.count() == 0


@pytest.mark.django_db
def test_effective_dated_revision_regenerates_only_unprotected_future_items(
    schedule_context: ScheduleContext,
) -> None:
    create_weekly_anchor(schedule_context)
    source, original_revision = create_source(
        schedule_context,
        name="Weekly bill",
        rule=RecurrenceRule(
            Frequency.WEEKLY,
            date(2026, 8, 21),
            weekdays=(4,),
        ),
    )
    generate_periods(schedule_context)
    synchronize_occurrences(
        household=schedule_context.household,
        actor=schedule_context.user,
        window_start=date(2026, 8, 20),
        window_end=date(2026, 9, 10),
        request_id="request-original-occurrences",
    )
    protected = Occurrence.objects.get(source=source, nominal_date=date(2026, 9, 4))
    override_occurrence(
        occurrence=protected,
        actor=schedule_context.user,
        request_id="request-protect-override",
        reason="One-off vendor adjustment",
        planned_amount=Decimal("125.00"),
    )
    new_spec = RevisionSpec(
        effective_from=date(2026, 9, 1),
        expected_amount=Decimal("120.00"),
        rule=RecurrenceRule(
            Frequency.WEEKLY,
            date(2026, 9, 7),
            weekdays=(0,),
        ),
        adjustment_policy=BusinessDayAdjustment.NONE,
    )
    new_preview = preview_revision(new_spec, preview_from=new_spec.effective_from)
    new_revision = revise_recurring_source(
        source=source,
        actor=schedule_context.user,
        revision_spec=new_spec,
        expected_preview_fingerprint=new_preview.fingerprint,
        request_id="request-schedule-revision",
        reason="Vendor changed its billing day",
    )
    result = synchronize_occurrences(
        household=schedule_context.household,
        actor=schedule_context.user,
        window_start=date(2026, 8, 20),
        window_end=date(2026, 9, 10),
        request_id="request-revised-occurrences",
    )

    protected.refresh_from_db()
    assert protected.status == Occurrence.Status.OVERRIDDEN
    assert protected.planned_amount == Decimal("125.00")
    assert Occurrence.objects.get(
        source_revision=new_revision,
        nominal_date=date(2026, 9, 7),
    ).planned_amount == Decimal("120.00")
    assert (
        Occurrence.objects.get(
            source_revision=original_revision,
            nominal_date=date(2026, 8, 28),
        ).status
        == Occurrence.Status.SCHEDULED
    )
    assert result.protected_count == 1

    original_revision.expected_amount = Decimal("1.00")
    with pytest.raises(ValidationError, match="cannot be updated"):
        original_revision.save()
    with pytest.raises(ValidationError, match="cannot be updated"):
        SourceRevision.objects.filter(pk=original_revision.pk).update(expected_amount=Decimal("1"))
    with pytest.raises(ValidationError, match="cannot be updated"):
        SourceRevision.objects.bulk_update([original_revision], ["expected_amount"])


@pytest.mark.django_db
def test_anchor_schedule_revision_rebuilds_only_projected_future_boundaries(
    schedule_context: ScheduleContext,
) -> None:
    anchor, original_revision = create_weekly_anchor(schedule_context)
    generate_periods(schedule_context, window_end=date(2026, 9, 17))
    synchronize_occurrences(
        household=schedule_context.household,
        actor=schedule_context.user,
        window_start=date(2026, 8, 20),
        window_end=date(2026, 9, 17),
        request_id="request-original-anchor-occurrences",
    )
    old_september_occurrence = Occurrence.objects.get(
        source_revision=original_revision,
        nominal_date=date(2026, 9, 3),
    )
    new_spec = RevisionSpec(
        effective_from=date(2026, 9, 1),
        expected_amount=Decimal("1500.00"),
        rule=RecurrenceRule(
            Frequency.WEEKLY,
            date(2026, 9, 4),
            weekdays=(4,),
        ),
        adjustment_policy=BusinessDayAdjustment.NONE,
    )
    new_preview = preview_revision(new_spec, preview_from=new_spec.effective_from)
    new_revision = revise_recurring_source(
        source=anchor,
        actor=schedule_context.user,
        revision_spec=new_spec,
        expected_preview_fingerprint=new_preview.fingerprint,
        request_id="request-anchor-schedule-revision",
        reason="Employer changed payday",
    )
    period_preview = preview_period_sync(
        household=schedule_context.household,
        window_start=date(2026, 8, 20),
        window_end=date(2026, 9, 17),
    )
    assert not period_preview.conflicts
    apply_period_sync(
        household=schedule_context.household,
        actor=schedule_context.user,
        window_start=date(2026, 8, 20),
        window_end=date(2026, 9, 17),
        expected_preview_fingerprint=period_preview.fingerprint,
        request_id="request-rebuild-future-periods",
    )
    synchronize_occurrences(
        household=schedule_context.household,
        actor=schedule_context.user,
        window_start=date(2026, 8, 20),
        window_end=date(2026, 9, 17),
        request_id="request-rebuild-anchor-occurrences",
    )

    old_september_occurrence.refresh_from_db()
    assert old_september_occurrence.status == Occurrence.Status.SUPERSEDED
    assert old_september_occurrence.pay_period is None
    assert PayPeriod.objects.filter(start_date=date(2026, 9, 4)).exists()
    assert not PayPeriod.objects.filter(start_date=date(2026, 9, 3)).exists()
    assert Occurrence.objects.filter(
        source_revision=new_revision,
        nominal_date=date(2026, 9, 4),
        status=Occurrence.Status.SCHEDULED,
    ).exists()


@pytest.mark.django_db
def test_occurrence_move_override_and_series_cancel_preserve_source_history(
    schedule_context: ScheduleContext,
) -> None:
    create_weekly_anchor(schedule_context)
    source, revision = create_source(
        schedule_context,
        name="Friday expense",
        rule=RecurrenceRule(Frequency.WEEKLY, date(2026, 8, 21), weekdays=(4,)),
    )
    generate_periods(schedule_context)
    synchronize_occurrences(
        household=schedule_context.household,
        actor=schedule_context.user,
        window_start=date(2026, 8, 20),
        window_end=date(2026, 9, 10),
        request_id="request-series-sync",
    )
    first, second, third = list(Occurrence.objects.filter(source=source).order_by("nominal_date"))[
        :3
    ]
    target = PayPeriod.objects.get(start_date=date(2026, 8, 27))
    moved = move_occurrence(
        occurrence=first,
        target_period=target,
        actor=schedule_context.user,
        request_id="request-move-once",
        reason="Pay after the next check",
    )
    assert moved.original_pay_period_id is not None
    assert second.pay_period_id == target.pk
    with pytest.raises(ValidationError, match="only once"):
        move_occurrence(
            occurrence=moved,
            target_period=PayPeriod.objects.get(start_date=date(2026, 9, 3)),
            actor=schedule_context.user,
            request_id="request-move-twice",
            reason="Changed our minds",
        )

    overridden = override_occurrence(
        occurrence=second,
        actor=schedule_context.user,
        request_id="request-override-one",
        reason="Temporary discount",
        planned_amount=Decimal("80.00"),
        expected_date=date(2026, 8, 29),
    )
    assert overridden.generated_amount == Decimal("100.00")
    assert overridden.generated_expected_date == date(2026, 8, 28)
    with pytest.raises(ValidationError, match="must remain"):
        override_occurrence(
            occurrence=overridden,
            actor=schedule_context.user,
            request_id="request-invalid-date-override",
            reason="Would cross a boundary",
            expected_date=date(2026, 9, 5),
        )

    complete_occurrence(
        occurrence=first,
        actor=schedule_context.user,
        actual_amount=Decimal("100.00"),
        actual_date=date(2026, 8, 21),
        request_id="request-complete-first",
    )
    cancelled = cancel_occurrence_and_future(
        occurrence=third,
        actor=schedule_context.user,
        request_id="request-cancel-series",
        reason="Service ended",
    )
    first.refresh_from_db()
    source.refresh_from_db()
    revision.refresh_from_db()
    assert cancelled >= 1
    assert first.status == Occurrence.Status.COMPLETED
    assert source.archived_from == third.nominal_date
    assert revision.end_date is None
    assert AuditEvent.objects.filter(action="schedule.series_cancelled").exists()


@pytest.mark.django_db
def test_actual_paycheck_requires_decision_and_confirmed_boundary_survives_refresh(
    schedule_context: ScheduleContext,
) -> None:
    anchor, _ = create_weekly_anchor(schedule_context)
    create_source(
        schedule_context,
        name="Wednesday bill",
        rule=RecurrenceRule(Frequency.ONCE, date(2026, 8, 26)),
    )
    generate_periods(schedule_context)
    synchronize_occurrences(
        household=schedule_context.household,
        actor=schedule_context.user,
        window_start=date(2026, 8, 20),
        window_end=date(2026, 9, 10),
        request_id="request-boundary-occurrences",
    )
    paycheck = Occurrence.objects.get(source=anchor, nominal_date=date(2026, 8, 27))
    bill = Occurrence.objects.get(source__name="Wednesday bill")
    with pytest.raises(ValidationError, match="Choose whether"):
        complete_occurrence(
            occurrence=paycheck,
            actor=schedule_context.user,
            actual_amount=Decimal("1500.00"),
            actual_date=date(2026, 8, 26),
            request_id="request-missing-boundary-decision",
        )

    preview = preview_boundary_change(
        occurrence=paycheck,
        actor=schedule_context.user,
        actual_date=date(2026, 8, 26),
    )
    assert not preview.conflicts
    complete_occurrence(
        occurrence=paycheck,
        actor=schedule_context.user,
        actual_amount=Decimal("1500.00"),
        actual_date=date(2026, 8, 26),
        boundary_decision="move",
        boundary_preview_fingerprint=preview.fingerprint,
        request_id="request-confirm-boundary-move",
    )
    bill.refresh_from_db()
    moved_period = PayPeriod.objects.get(start_date=date(2026, 8, 26))
    previous = PayPeriod.objects.get(start_date=date(2026, 8, 20))
    assert bill.pay_period == moved_period
    assert previous.next_start_date == date(2026, 8, 26)
    assert moved_period.boundary_source == PayPeriod.BoundarySource.ACTUAL

    next_paycheck = Occurrence.objects.get(source=anchor, nominal_date=date(2026, 9, 3))
    complete_occurrence(
        occurrence=next_paycheck,
        actor=schedule_context.user,
        actual_amount=Decimal("1500.00"),
        actual_date=date(2026, 9, 2),
        boundary_decision="keep",
        request_id="request-keep-projected-boundary",
    )
    assert PayPeriod.objects.get(start_date=date(2026, 9, 3)).boundary_source == (
        PayPeriod.BoundarySource.EXPECTED
    )

    refreshed = preview_period_sync(
        household=schedule_context.household,
        window_start=date(2026, 8, 20),
        window_end=date(2026, 9, 10),
    )
    assert refreshed.create_ranges == ()
    assert refreshed.resize_periods == ()
    assert refreshed.remove_period_ids == ()
    assert refreshed.conflicts == ()


@pytest.mark.django_db
def test_period_state_refresh_and_closed_period_occurrence_guard(
    schedule_context: ScheduleContext,
) -> None:
    previous = PayPeriod.objects.create(
        household=schedule_context.household,
        start_date=date(2026, 8, 13),
        next_start_date=date(2026, 8, 20),
        status=PayPeriod.Status.OPEN,
        created_by=schedule_context.user,
    )
    current = PayPeriod.objects.create(
        household=schedule_context.household,
        start_date=date(2026, 8, 20),
        next_start_date=date(2026, 8, 27),
        status=PayPeriod.Status.PROJECTED,
        created_by=schedule_context.user,
    )
    assert refresh_period_states(
        household=schedule_context.household,
        actor=schedule_context.user,
        today=date(2026, 8, 21),
        request_id="request-refresh-period-states",
    ) == (1, 1)
    previous.refresh_from_db()
    current.refresh_from_db()
    assert previous.status == PayPeriod.Status.CLOSING_REVIEW
    assert current.status == PayPeriod.Status.OPEN

    source, revision = create_source(
        schedule_context,
        name="Closed-period item",
        rule=RecurrenceRule(Frequency.ONCE, date(2026, 8, 21)),
    )
    occurrence = Occurrence.objects.create(
        source=source,
        source_revision=revision,
        nominal_date=date(2026, 8, 21),
        generated_expected_date=date(2026, 8, 21),
        expected_date=date(2026, 8, 21),
        generated_amount=Decimal("100.00"),
        planned_amount=Decimal("100.00"),
        pay_period=current,
    )
    current.status = PayPeriod.Status.CLOSED
    current.save(update_fields=("status", "updated_at"))
    with pytest.raises(ValidationError, match="Reopen the closed"):
        override_occurrence(
            occurrence=occurrence,
            actor=schedule_context.user,
            request_id="request-edit-closed-occurrence",
            reason="Should require historical workflow",
            planned_amount=Decimal("90.00"),
        )


@pytest.mark.django_db
def test_period_close_reopen_posts_only_reserve_delta_and_history_is_immutable(
    schedule_context: ScheduleContext,
) -> None:
    closed_period = PayPeriod.objects.create(
        household=schedule_context.household,
        start_date=date(2026, 8, 20),
        next_start_date=date(2026, 8, 27),
        status=PayPeriod.Status.OPEN,
        created_by=schedule_context.user,
    )
    current_period = PayPeriod.objects.create(
        household=schedule_context.household,
        start_date=date(2026, 8, 27),
        next_start_date=date(2026, 9, 3),
        status=PayPeriod.Status.OPEN,
        created_by=schedule_context.user,
    )
    first = close_period(
        pay_period=closed_period,
        actor=schedule_context.user,
        closing_surplus=Decimal("429.90"),
        request_id="request-close-period",
    )
    reopen_period(
        pay_period=closed_period,
        actor=schedule_context.user,
        request_id="request-reopen-period",
        reason="A late transaction was entered",
    )
    correction = close_period(
        pay_period=closed_period,
        actor=schedule_context.user,
        closing_surplus=Decimal("404.90"),
        posting_period=current_period,
        request_id="request-correct-period",
        reason="Included the late transaction",
    )

    assert first.reserve_delta == Decimal("429.90")
    assert correction.reserve_delta == Decimal("-25.00")
    assert list(ReserveEntry.objects.values_list("amount", flat=True)) == [
        Decimal("429.90"),
        Decimal("-25.00"),
    ]
    assert reserve_balance(schedule_context.household) == Decimal("404.90")
    current_period.refresh_from_db()
    assert current_period.status == PayPeriod.Status.OPEN
    with pytest.raises(ValidationError, match="cannot be updated"):
        PayPeriodClosingRevision.objects.filter(pk=first.pk).update(reason="tampered")
    with pytest.raises(ValidationError, match="cannot be deleted"):
        ReserveEntry.objects.all().delete()
    with pytest.raises(ValidationError, match="must use"):
        ReserveEntry.objects.bulk_create([])


@pytest.mark.django_db
def test_period_close_rolls_back_domain_reserve_and_audit_together(
    schedule_context: ScheduleContext,
) -> None:
    period = PayPeriod.objects.create(
        household=schedule_context.household,
        start_date=date(2026, 8, 20),
        next_start_date=date(2026, 8, 27),
        status=PayPeriod.Status.OPEN,
        created_by=schedule_context.user,
    )
    with (
        patch("periods.services.lifecycle.append_event", side_effect=RuntimeError("audit failed")),
        pytest.raises(RuntimeError, match="audit failed"),
    ):
        close_period(
            pay_period=period,
            actor=schedule_context.user,
            closing_surplus=Decimal("10.00"),
            request_id="request-rollback-close",
        )

    period.refresh_from_db()
    assert period.status == PayPeriod.Status.OPEN
    assert PayPeriodClosingRevision.objects.count() == 0
    assert ReserveEntry.objects.count() == 0
    assert AuditEvent.objects.count() == 0


@pytest.mark.django_db
def test_scheduling_mutations_are_household_authorized_and_secrets_are_rejected(
    schedule_context: ScheduleContext,
) -> None:
    rule = RecurrenceRule(Frequency.ONCE, date(2026, 8, 20))
    specification = RevisionSpec(
        effective_from=rule.start_date,
        expected_amount=Decimal("1.00"),
        rule=rule,
        configuration={"token": "do-not-store-this"},
    )
    with pytest.raises(ValidationError, match="Sensitive schedule configuration"):
        preview_revision(specification, preview_from=rule.start_date)

    safe_specification = RevisionSpec(
        effective_from=rule.start_date,
        expected_amount=Decimal("1.00"),
        rule=rule,
    )
    preview = preview_revision(safe_specification, preview_from=rule.start_date)
    with pytest.raises(PermissionDenied):
        create_recurring_source(
            household=schedule_context.household,
            actor=schedule_context.outsider,
            kind=RecurringSource.Kind.INCOME,
            name="Unauthorized income",
            revision_spec=safe_specification,
            expected_preview_fingerprint=preview.fingerprint,
            request_id="request-unauthorized-source",
        )
    assert RecurringSource.objects.count() == 0
    assert AuditEvent.objects.count() == 0
