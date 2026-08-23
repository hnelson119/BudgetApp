from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import date, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any

from django.core.exceptions import ValidationError
from django.db import transaction

from audit.services import append_event
from households.models import Category, Household
from households.services.access import require_household_membership
from identity.models import User
from schedules.models import (
    ExpenseSourceDetail,
    IncomeSourceDetail,
    RecurringSource,
    SourceRevision,
)
from schedules.recurrence import (
    BusinessDayAdjustment,
    Frequency,
    ProjectedOccurrenceDate,
    RecurrenceRule,
    project_occurrences,
)

_CENT = Decimal("0.01")
_MAX_CONFIGURATION_BYTES = 10_000
_SENSITIVE_KEYS = {"password", "pin", "secret", "token", "username"}


@dataclass(frozen=True, slots=True)
class RevisionSpec:
    effective_from: date
    expected_amount: Decimal
    rule: RecurrenceRule
    adjustment_policy: BusinessDayAdjustment = BusinessDayAdjustment.PREVIOUS
    holiday_dates: tuple[date, ...] = ()
    configuration: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class RevisionPreview:
    next_occurrences: tuple[ProjectedOccurrenceDate, ...]
    fingerprint: str


def _money(value: Decimal) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ValidationError("Scheduled amounts must use finite Decimal values.")
    try:
        normalized = value.quantize(_CENT)
    except InvalidOperation as error:
        raise ValidationError("Scheduled amount is invalid.") from error
    if normalized != value or normalized < 0:
        raise ValidationError("Scheduled amounts must be nonnegative with at most two decimals.")
    return normalized


def _validate_json_value(value: Any, path: tuple[str, ...] = ()) -> None:
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        raise ValidationError(
            f"Floating-point schedule configuration is invalid at {'.'.join(path)}."
        )
    if isinstance(value, list):
        for index, child in enumerate(value):
            _validate_json_value(child, (*path, str(index)))
        return
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValidationError("Schedule configuration keys must be strings.")
            normalized_key = key.strip()
            if normalized_key.casefold() in _SENSITIVE_KEYS:
                raise ValidationError(
                    f"Sensitive schedule configuration key {key!r} is prohibited."
                )
            _validate_json_value(child, (*path, normalized_key))
        return
    raise ValidationError(f"Unsupported schedule configuration at {'.'.join(path)}.")


def _configuration(value: dict[str, Any] | None) -> dict[str, Any]:
    configuration = value or {}
    if not isinstance(configuration, dict):
        raise ValidationError("Schedule configuration must be an object.")
    _validate_json_value(configuration)
    encoded = json.dumps(configuration, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > _MAX_CONFIGURATION_BYTES:
        raise ValidationError("Schedule configuration is too large.")
    return configuration


def _validate_spec(spec: RevisionSpec) -> tuple[Decimal, dict[str, Any]]:
    spec.rule.validate()
    if spec.rule.start_date < spec.effective_from:
        raise ValidationError("A revision recurrence cannot start before it becomes effective.")
    try:
        BusinessDayAdjustment(spec.adjustment_policy)
    except ValueError as error:
        raise ValidationError("Business-day adjustment policy is invalid.") from error
    if len(spec.holiday_dates) > 366:
        raise ValidationError("A schedule revision cannot contain more than 366 holiday dates.")
    if len(set(spec.holiday_dates)) != len(spec.holiday_dates):
        raise ValidationError("A schedule revision cannot repeat a holiday date.")
    return _money(spec.expected_amount), _configuration(spec.configuration)


def _preview_payload(
    spec: RevisionSpec,
    projected: tuple[ProjectedOccurrenceDate, ...],
) -> dict[str, Any]:
    rule_payload = asdict(spec.rule)
    rule_payload["frequency"] = spec.rule.frequency.value
    for key in ("start_date", "end_date"):
        value = rule_payload[key]
        rule_payload[key] = value.isoformat() if value else None
    return {
        "effective_from": spec.effective_from.isoformat(),
        "expected_amount": format(spec.expected_amount, "f"),
        "rule": rule_payload,
        "adjustment_policy": spec.adjustment_policy.value,
        "holiday_dates": [value.isoformat() for value in sorted(spec.holiday_dates)],
        "configuration": _configuration(spec.configuration),
        "next_occurrences": [
            [value.nominal_date.isoformat(), value.expected_date.isoformat()] for value in projected
        ],
    }


def preview_revision(spec: RevisionSpec, *, preview_from: date) -> RevisionPreview:
    _validate_spec(spec)
    projection_start = max(spec.rule.start_date, preview_from - timedelta(days=367))
    projection_end = preview_from + timedelta(days=366 * 10)
    projected = tuple(
        value
        for value in project_occurrences(
            spec.rule,
            window_start=projection_start,
            window_end=projection_end,
            adjustment=spec.adjustment_policy,
            holidays=frozenset(spec.holiday_dates),
        )
        if value.expected_date >= preview_from
    )[:3]
    payload = _preview_payload(spec, projected)
    fingerprint = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return RevisionPreview(projected, fingerprint)


def rule_from_revision(revision: SourceRevision) -> RecurrenceRule:
    return RecurrenceRule(
        frequency=Frequency(revision.frequency),
        start_date=revision.start_date,
        end_date=revision.end_date,
        interval=revision.interval,
        weekdays=tuple(revision.weekdays),
        day_of_month=revision.day_of_month,
        weekday=revision.weekday,
        ordinal=revision.ordinal,
        month_of_year=revision.month_of_year,
    )


def holidays_from_revision(revision: SourceRevision) -> frozenset[date]:
    try:
        return frozenset(date.fromisoformat(value) for value in revision.holiday_dates)
    except (TypeError, ValueError) as error:
        raise ValidationError("Stored schedule holiday dates are invalid.") from error


def _create_revision(
    *,
    source: RecurringSource,
    actor: User,
    revision_number: int,
    spec: RevisionSpec,
) -> SourceRevision:
    expected_amount, configuration = _validate_spec(spec)
    revision = SourceRevision(
        source=source,
        revision_number=revision_number,
        effective_from=spec.effective_from,
        expected_amount=expected_amount,
        frequency=spec.rule.frequency.value,
        interval=spec.rule.interval,
        start_date=spec.rule.start_date,
        end_date=spec.rule.end_date,
        weekdays=list(spec.rule.weekdays),
        day_of_month=spec.rule.day_of_month,
        weekday=spec.rule.weekday,
        ordinal=spec.rule.ordinal,
        month_of_year=spec.rule.month_of_year,
        adjustment_policy=spec.adjustment_policy.value,
        holiday_dates=[value.isoformat() for value in sorted(spec.holiday_dates)],
        configuration=configuration,
        created_by=actor,
    )
    revision.full_clean()
    revision._service_authorized = True  # type: ignore[attr-defined]
    revision.save()
    return revision


@transaction.atomic
def create_recurring_source(
    *,
    household: Household,
    actor: User,
    kind: str,
    name: str,
    revision_spec: RevisionSpec,
    expected_preview_fingerprint: str,
    request_id: str,
    notes: str = "",
    starts_budget_period: bool = False,
    is_variable_income: bool = False,
    expense_category: Category | None = None,
    is_required_expense: bool = True,
) -> tuple[RecurringSource, SourceRevision]:
    require_household_membership(actor, household)
    if kind not in RecurringSource.Kind.values:
        raise ValidationError("Recurring source kind is invalid.")
    preview = preview_revision(revision_spec, preview_from=revision_spec.effective_from)
    if preview.fingerprint != expected_preview_fingerprint:
        raise ValidationError("The schedule preview is stale; preview it again before saving.")
    source = RecurringSource(
        household=household,
        kind=kind,
        name=name.strip(),
        notes=notes.strip(),
        created_by=actor,
    )
    source.full_clean()
    source.save()
    if kind == RecurringSource.Kind.INCOME:
        if expense_category is not None:
            raise ValidationError("Income sources cannot use an expense category.")
        income_detail = IncomeSourceDetail(
            source=source,
            starts_budget_period=starts_budget_period,
            is_variable=is_variable_income,
        )
        income_detail.full_clean()
        income_detail.save()
    elif kind == RecurringSource.Kind.FIXED_EXPENSE:
        if expense_category is not None:
            category = Category.objects.select_for_update().get(pk=expense_category.pk)
            if category.household_id != household.pk:
                raise ValidationError("The expense category belongs to another household.")
            if category.is_archived:
                raise ValidationError("Archived categories cannot be used for new fixed expenses.")
            expense_detail = ExpenseSourceDetail(
                source=source,
                category=category,
                is_required=is_required_expense,
            )
            expense_detail.full_clean()
            expense_detail.save()
    elif starts_budget_period or is_variable_income:
        raise ValidationError("Only income sources can use income schedule settings.")
    elif expense_category is not None:
        raise ValidationError("Only fixed expenses can use an expense category.")
    revision = _create_revision(
        source=source,
        actor=actor,
        revision_number=1,
        spec=revision_spec,
    )
    append_event(
        household=household,
        actor=actor,
        action="schedule.source_created",
        entity_type="recurring_source",
        entity_id=source.pk,
        request_id=request_id,
        after={
            "kind": source.kind,
            "name": source.name,
            "revision_id": revision.pk,
            "starts_budget_period": starts_budget_period,
            "category_id": expense_category.pk if expense_category else None,
            "is_required_expense": is_required_expense if expense_category else None,
        },
    )
    return source, revision


@transaction.atomic
def revise_recurring_source(
    *,
    source: RecurringSource,
    actor: User,
    revision_spec: RevisionSpec,
    expected_preview_fingerprint: str,
    request_id: str,
    reason: str,
) -> SourceRevision:
    locked = (
        RecurringSource.objects.select_for_update().select_related("household").get(pk=source.pk)
    )
    require_household_membership(actor, locked.household)
    if locked.is_archived:
        raise ValidationError("Archived recurring sources cannot be revised.")
    if not reason.strip():
        raise ValidationError("Schedule revisions require a reason.")
    preview = preview_revision(revision_spec, preview_from=revision_spec.effective_from)
    if preview.fingerprint != expected_preview_fingerprint:
        raise ValidationError("The schedule preview is stale; preview it again before saving.")
    latest = locked.revisions.order_by("-revision_number").first()
    if latest is None:
        raise ValidationError("The recurring source has no initial revision.")
    if revision_spec.effective_from <= latest.effective_from:
        raise ValidationError("A new revision must take effect after the latest revision.")
    revision = _create_revision(
        source=locked,
        actor=actor,
        revision_number=latest.revision_number + 1,
        spec=revision_spec,
    )
    append_event(
        household=locked.household,
        actor=actor,
        action="schedule.revision_created",
        entity_type="source_revision",
        entity_id=revision.pk,
        request_id=request_id,
        before={
            "revision_id": latest.pk,
            "revision_number": latest.revision_number,
        },
        after={
            "revision_number": revision.revision_number,
            "effective_from": revision.effective_from,
            "frequency": revision.frequency,
        },
        reason=reason.strip(),
    )
    return revision
