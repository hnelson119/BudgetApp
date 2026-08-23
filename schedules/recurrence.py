from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import date, timedelta
from enum import StrEnum

from django.core.exceptions import ValidationError

_MAX_WINDOW_DAYS = 366 * 25
_MAX_OCCURRENCES = 10_000


class Frequency(StrEnum):
    ONCE = "once"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY_DAY = "monthly_day"
    MONTHLY_NTH_WEEKDAY = "monthly_nth_weekday"
    MONTHLY_LAST_WEEKDAY = "monthly_last_weekday"
    ANNUAL = "annual"


class BusinessDayAdjustment(StrEnum):
    NONE = "none"
    PREVIOUS = "previous"
    NEXT = "next"


@dataclass(frozen=True, slots=True)
class RecurrenceRule:
    frequency: Frequency
    start_date: date
    end_date: date | None = None
    interval: int = 1
    weekdays: tuple[int, ...] = ()
    day_of_month: int | None = None
    weekday: int | None = None
    ordinal: int | None = None
    month_of_year: int | None = None

    def validate(self) -> None:
        if self.interval < 1 or self.interval > 366:
            raise ValidationError("Recurrence interval must be between 1 and 366.")
        if self.end_date is not None and self.end_date < self.start_date:
            raise ValidationError("Recurrence end date cannot precede its start date.")
        if any(day < 0 or day > 6 for day in self.weekdays):
            raise ValidationError("Weekdays must use values from Monday 0 through Sunday 6.")
        if len(set(self.weekdays)) != len(self.weekdays):
            raise ValidationError("A recurrence weekday cannot be repeated.")

        if self.frequency == Frequency.WEEKLY:
            if not self.weekdays:
                raise ValidationError("Weekly recurrence requires at least one weekday.")
        elif self.weekdays:
            raise ValidationError("Selected weekdays are only valid for weekly recurrence.")

        if self.frequency in (Frequency.MONTHLY_DAY, Frequency.ANNUAL):
            if self.day_of_month is None or not 1 <= self.day_of_month <= 31:
                raise ValidationError("This recurrence requires a day of month from 1 through 31.")
        elif self.day_of_month is not None:
            raise ValidationError("Day of month is invalid for this recurrence type.")

        if self.frequency in (
            Frequency.MONTHLY_NTH_WEEKDAY,
            Frequency.MONTHLY_LAST_WEEKDAY,
        ):
            if self.weekday is None or not 0 <= self.weekday <= 6:
                raise ValidationError("This recurrence requires a weekday.")
        elif self.weekday is not None:
            raise ValidationError("Weekday is invalid for this recurrence type.")

        if self.frequency == Frequency.MONTHLY_NTH_WEEKDAY:
            if self.ordinal is None or not 1 <= self.ordinal <= 5:
                raise ValidationError(
                    "Nth-weekday recurrence requires an ordinal from 1 through 5."
                )
        elif self.ordinal is not None:
            raise ValidationError("Ordinal is invalid for this recurrence type.")

        if self.frequency == Frequency.ANNUAL:
            if self.month_of_year is None or not 1 <= self.month_of_year <= 12:
                raise ValidationError("Annual recurrence requires a month from 1 through 12.")
        elif self.month_of_year is not None:
            raise ValidationError("Month of year is invalid for this recurrence type.")


@dataclass(frozen=True, slots=True)
class ProjectedOccurrenceDate:
    nominal_date: date
    expected_date: date


def _month_index(value: date) -> int:
    return value.year * 12 + value.month - 1


def _month_parts(index: int) -> tuple[int, int]:
    return divmod(index, 12)[0], divmod(index, 12)[1] + 1


def _clamped_date(year: int, month: int, day: int) -> date:
    return date(year, month, min(day, calendar.monthrange(year, month)[1]))


def _nth_weekday(year: int, month: int, weekday: int, ordinal: int) -> date | None:
    first = date(year, month, 1)
    candidate = first + timedelta(days=(weekday - first.weekday()) % 7 + (ordinal - 1) * 7)
    return candidate if candidate.month == month else None


def _last_weekday(year: int, month: int, weekday: int) -> date:
    last = date(year, month, calendar.monthrange(year, month)[1])
    return last - timedelta(days=(last.weekday() - weekday) % 7)


def _bounded_window(
    rule: RecurrenceRule, window_start: date, window_end: date
) -> tuple[date, date]:
    rule.validate()
    if window_end < window_start:
        raise ValidationError("Recurrence preview end cannot precede its start.")
    if (window_end - window_start).days > _MAX_WINDOW_DAYS:
        raise ValidationError("Recurrence preview windows cannot exceed 25 years.")
    bounded_start = max(window_start, rule.start_date)
    bounded_end = min(window_end, rule.end_date) if rule.end_date else window_end
    return bounded_start, bounded_end


def occurrences_between(
    rule: RecurrenceRule,
    *,
    window_start: date,
    window_end: date,
    limit: int = _MAX_OCCURRENCES,
) -> tuple[date, ...]:
    """Generate deterministic nominal dates in an inclusive, bounded window."""

    if limit < 1 or limit > _MAX_OCCURRENCES:
        raise ValidationError("Recurrence result limit is invalid.")
    start, end = _bounded_window(rule, window_start, window_end)
    if end < start:
        return ()

    candidates: list[date] = []
    if rule.frequency == Frequency.ONCE:
        if start <= rule.start_date <= end:
            candidates.append(rule.start_date)
    elif rule.frequency == Frequency.DAILY:
        elapsed = (start - rule.start_date).days
        offset = ((elapsed + rule.interval - 1) // rule.interval) * rule.interval
        candidate = rule.start_date + timedelta(days=offset)
        while candidate <= end:
            candidates.append(candidate)
            candidate += timedelta(days=rule.interval)
    elif rule.frequency == Frequency.WEEKLY:
        selected = set(rule.weekdays)
        candidate = start
        while candidate <= end:
            week_index = (candidate - rule.start_date).days // 7
            if week_index % rule.interval == 0 and candidate.weekday() in selected:
                candidates.append(candidate)
            candidate += timedelta(days=1)
    elif rule.frequency in (
        Frequency.MONTHLY_DAY,
        Frequency.MONTHLY_NTH_WEEKDAY,
        Frequency.MONTHLY_LAST_WEEKDAY,
    ):
        anchor_month = _month_index(rule.start_date)
        first_month = max(anchor_month, _month_index(start))
        last_month = _month_index(end)
        for month_index in range(first_month, last_month + 1):
            if (month_index - anchor_month) % rule.interval:
                continue
            year, month = _month_parts(month_index)
            month_candidate: date | None
            if rule.frequency == Frequency.MONTHLY_DAY:
                if rule.day_of_month is None:
                    raise ValidationError("Monthly recurrence is missing its day of month.")
                month_candidate = _clamped_date(year, month, rule.day_of_month)
            elif rule.frequency == Frequency.MONTHLY_NTH_WEEKDAY:
                if rule.weekday is None or rule.ordinal is None:
                    raise ValidationError("Nth-weekday recurrence is incomplete.")
                month_candidate = _nth_weekday(year, month, rule.weekday, rule.ordinal)
            else:
                if rule.weekday is None:
                    raise ValidationError("Last-weekday recurrence is missing its weekday.")
                month_candidate = _last_weekday(year, month, rule.weekday)
            if month_candidate is None:
                continue
            if start <= month_candidate <= end and month_candidate >= rule.start_date:
                candidates.append(month_candidate)
    elif rule.frequency == Frequency.ANNUAL:
        if rule.month_of_year is None or rule.day_of_month is None:
            raise ValidationError("Annual recurrence is incomplete.")
        first_year = max(start.year, rule.start_date.year)
        for year in range(first_year, end.year + 1):
            if (year - rule.start_date.year) % rule.interval:
                continue
            candidate = _clamped_date(year, rule.month_of_year, rule.day_of_month)
            if start <= candidate <= end and candidate >= rule.start_date:
                candidates.append(candidate)

    if len(candidates) > limit:
        raise ValidationError("Recurrence generated more occurrences than the allowed limit.")
    return tuple(candidates)


def adjust_business_day(
    value: date,
    *,
    policy: BusinessDayAdjustment,
    holidays: frozenset[date] = frozenset(),
) -> date:
    try:
        normalized_policy = BusinessDayAdjustment(policy)
    except ValueError as error:
        raise ValidationError("Business-day adjustment policy is invalid.") from error
    if normalized_policy == BusinessDayAdjustment.NONE:
        return value
    if value.weekday() < 5 and value not in holidays:
        return value
    step = -1 if normalized_policy == BusinessDayAdjustment.PREVIOUS else 1
    adjusted = value
    for _ in range(367):
        if adjusted.weekday() < 5 and adjusted not in holidays:
            return adjusted
        adjusted += timedelta(days=step)
    raise ValidationError("Business-day adjustment could not find an eligible date.")


def project_occurrences(
    rule: RecurrenceRule,
    *,
    window_start: date,
    window_end: date,
    adjustment: BusinessDayAdjustment = BusinessDayAdjustment.NONE,
    holidays: frozenset[date] = frozenset(),
    limit: int = _MAX_OCCURRENCES,
) -> tuple[ProjectedOccurrenceDate, ...]:
    return tuple(
        ProjectedOccurrenceDate(
            nominal_date=nominal,
            expected_date=adjust_business_day(nominal, policy=adjustment, holidays=holidays),
        )
        for nominal in occurrences_between(
            rule,
            window_start=window_start,
            window_end=window_end,
            limit=limit,
        )
    )
