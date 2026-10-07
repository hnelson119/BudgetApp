from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import ROUND_UP, Decimal
from zoneinfo import ZoneInfo

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from audit.services import append_event
from budgets.services.calculations import money
from debts.models import DebtAccount, DebtPromotionRevision
from debts.services.accounts import _money, _rate, current_debt_terms
from households.models import Household
from households.services.access import require_household_membership
from identity.models import User
from periods.models import PayPeriod
from schedules.models import Occurrence

ZERO = Decimal("0.00")


@dataclass(frozen=True, slots=True)
class PromotionSpec:
    kind: str
    as_of: date
    expires_on: date | None = None
    promotional_apr: Decimal | None = None
    regular_apr: Decimal | None = None
    accrued_interest: Decimal | None = None


def latest_promotion(debt: DebtAccount) -> DebtPromotionRevision | None:
    return debt.promotion_revisions.order_by("-revision_number").first()


def effective_apr(debt: DebtAccount, *, on_date: date) -> Decimal:
    terms = current_debt_terms(debt, on_date=on_date)
    promotion = latest_promotion(debt)
    if (
        promotion is not None
        and promotion.kind != DebtPromotionRevision.Kind.NONE
        and on_date >= promotion.as_of
    ):
        if (
            promotion.expires_on is None
            or promotion.promotional_apr is None
            or promotion.regular_apr is None
        ):
            raise ValidationError("Promotional terms are incomplete. Review the lender terms.")
        if on_date <= promotion.expires_on:
            return promotion.promotional_apr
        if terms.effective_from <= promotion.expires_on:
            return promotion.regular_apr
    return terms.annual_percentage_rate


@transaction.atomic
def save_promotion(
    *,
    debt: DebtAccount,
    actor: User,
    spec: PromotionSpec,
    expected_revision: int,
    expected_balance: Decimal,
    confirm_entire_balance: bool,
    request_id: str,
) -> DebtPromotionRevision:
    require_household_membership(actor, debt.household)
    Household.objects.select_for_update().get(pk=debt.household_id)
    locked = DebtAccount.objects.select_for_update().select_related("household").get(pk=debt.pk)
    require_household_membership(actor, locked.household)
    previous = latest_promotion(locked)
    if (
        expected_revision != (previous.revision_number if previous else 0)
        or expected_balance != locked.current_balance
    ):
        raise ValidationError(
            "The promotion or balance changed. Reload and review the terms again."
        )
    if not locked.is_active or locked.current_balance <= 0:
        raise ValidationError("Promotion tracking requires an active debt with a balance.")
    today = timezone.localdate(timezone=ZoneInfo(locked.household.time_zone))
    if spec.kind not in DebtPromotionRevision.Kind.values or spec.as_of > today:
        raise ValidationError(
            "Select a valid promotion and a current or historical statement date."
        )
    if spec.kind != DebtPromotionRevision.Kind.NONE and not confirm_entire_balance:
        raise ValidationError(
            "Confirm that this promotion applies to the entire tracked debt balance."
        )
    record = DebtPromotionRevision(
        debt=locked,
        revision_number=expected_revision + 1,
        kind=spec.kind,
        as_of=spec.as_of,
        expires_on=spec.expires_on,
        promotional_apr=_rate(spec.promotional_apr) if spec.promotional_apr is not None else None,
        regular_apr=_rate(spec.regular_apr) if spec.regular_apr is not None else None,
        accrued_interest=_money(spec.accrued_interest, "Accrued deferred interest")
        if spec.accrued_interest is not None
        else None,
        created_by=actor,
    )
    record.full_clean()
    record._service_authorized = True  # type: ignore[attr-defined]
    record.save()
    append_event(
        household=locked.household,
        actor=actor,
        action="debt.promotion_saved",
        entity_type="debt_promotion_revision",
        entity_id=record.pk,
        request_id=request_id,
        before={"revision_number": previous.revision_number if previous else 0},
        after={
            "kind": record.kind,
            "as_of": record.as_of,
            "expires_on": record.expires_on,
            "promotional_apr": record.promotional_apr,
            "regular_apr": record.regular_apr,
            "accrued_interest": record.accrued_interest,
        },
    )
    return record


@dataclass(frozen=True, slots=True)
class PromotionSummary:
    debt: DebtAccount
    revision: DebtPromotionRevision
    expired: bool
    periods_remaining: int
    total_per_period: Decimal
    extra_per_period: Decimal
    planned_before_deadline: Decimal
    stale_statement: bool
    estimated_interest_before_deadline: Decimal


def promotion_summary(debt: DebtAccount, *, today: date) -> PromotionSummary | None:
    promotion = latest_promotion(debt)
    if promotion is None or promotion.kind == DebtPromotionRevision.Kind.NONE:
        return None
    if promotion.expires_on is None:
        raise ValidationError("Promotion tracking requires a deadline.")
    terms = current_debt_terms(debt, on_date=today)
    basis = Decimal("360") if terms.day_count_basis == "actual_360" else Decimal("365")
    estimated_interest = money(
        debt.current_balance
        * (promotion.promotional_apr or ZERO)
        / Decimal("100")
        * max((promotion.expires_on - today).days + 1, 0)
        / basis
    )
    periods = PayPeriod.objects.filter(
        household=debt.household,
        next_start_date__gt=today,
        start_date__lte=promotion.expires_on,
        status__in=(PayPeriod.Status.PROJECTED, PayPeriod.Status.OPEN, PayPeriod.Status.REOPENED),
    ).count()
    planned = money(
        sum(
            (
                item.planned_amount
                for item in Occurrence.objects.filter(
                    source__household=debt.household,
                    source_revision__configuration__debt_account_id=str(debt.pk),
                    expected_date__gte=today,
                    expected_date__lte=promotion.expires_on,
                ).exclude(
                    status__in=(
                        Occurrence.Status.CANCELLED,
                        Occurrence.Status.SUPERSEDED,
                        Occurrence.Status.COMPLETED,
                        Occurrence.Status.CORRECTED,
                    )
                )
            ),
            ZERO,
        )
    )

    def per_period(amount: Decimal) -> Decimal:
        return (amount / periods).quantize(Decimal("0.01"), rounding=ROUND_UP) if periods else ZERO

    return PromotionSummary(
        debt,
        promotion,
        promotion.expires_on < today,
        periods,
        per_period(debt.current_balance + estimated_interest),
        per_period(max(debt.current_balance + estimated_interest - planned, ZERO)),
        planned,
        promotion.kind == DebtPromotionRevision.Kind.DEFERRED and promotion.as_of < today,
        estimated_interest,
    )
