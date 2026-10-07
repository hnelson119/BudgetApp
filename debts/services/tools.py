from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation

from django.core.exceptions import ValidationError

from audit.models import AuditEvent
from budgets.services.calculations import money
from debts.models import DebtAccount, DebtStatement, DebtTermsRevision
from debts.services.accounts import _money, current_debt_terms
from debts.services.projections import (
    PayoffProjection,
    PayoffStrategy,
    ProjectionDebt,
    ProjectionPromotion,
    ProjectionTerms,
    _add_months,
    project_debt_payoff,
)
from debts.services.promotions import effective_apr
from households.models import Household

ZERO = Decimal("0.00")
MAX_EXTRA = Decimal("1000000.00")


def _amount(value: Decimal, name: str, *, maximum: Decimal = MAX_EXTRA) -> Decimal:
    if (
        not isinstance(value, Decimal)
        or not value.is_finite()
        or not ZERO <= value <= maximum
        or value != money(value)
    ):
        raise ValidationError(f"{name} must be nonnegative dollars and cents within the limit.")
    return value


@dataclass(frozen=True, slots=True)
class TargetResult:
    required_extra: Decimal | None
    projection: PayoffProjection
    baseline: PayoffProjection
    target_date: date
    monthly_extra: Decimal
    average_days: Decimal


def solve_payoff_target(
    debts: tuple[ProjectionDebt, ...],
    *,
    start_date: date,
    target_date: date,
    strategy: str,
    average_days: Decimal,
    maximum_extra: Decimal,
) -> TargetResult:
    maximum_extra = _amount(maximum_extra, "Maximum extra per period")
    if (
        not debts
        or not average_days.is_finite()
        or not Decimal("1") <= average_days <= Decimal("366")
    ):
        raise ValidationError(
            "Add active debts and an income schedule with paycheck periods first."
        )
    if strategy not in (PayoffStrategy.AVALANCHE, PayoffStrategy.SNOWBALL, PayoffStrategy.CUSTOM):
        raise ValidationError("Select a supported payoff strategy.")
    if not _add_months(start_date, 1) <= target_date <= _add_months(start_date, 120):
        raise ValidationError(
            "Choose a target from one modeled month through ten years from today."
        )
    months = sum(_add_months(start_date, index) <= target_date for index in range(1, 121))

    def simulate(cents: int) -> PayoffProjection:
        monthly = money(Decimal(cents) / 100 * 365 / (average_days * 12))
        return project_debt_payoff(
            debts,
            strategy=PayoffStrategy(strategy),
            monthly_extra=monthly,
            start_date=start_date,
            max_months=months,
        )

    baseline = simulate(0)
    if baseline.paid_off:
        return TargetResult(ZERO, baseline, baseline, target_date, ZERO, average_days)
    upper = int(maximum_extra * 100)
    affordable = simulate(upper)
    if not affordable.paid_off:
        return TargetResult(
            None,
            affordable,
            baseline,
            target_date,
            money(maximum_extra * 365 / (average_days * 12)),
            average_days,
        )
    lower = 0
    while lower < upper:
        midpoint = (lower + upper) // 2
        if simulate(midpoint).paid_off:
            upper = midpoint
        else:
            lower = midpoint + 1
    required = Decimal(lower) / 100
    return TargetResult(
        required,
        simulate(lower),
        baseline,
        target_date,
        money(required * 365 / (average_days * 12)),
        average_days,
    )


@dataclass(frozen=True, slots=True)
class OfferSpec:
    annual_percentage_rate: Decimal
    monthly_payment: Decimal
    fee_percent: Decimal
    fixed_fee: Decimal
    finance_fees: bool
    expires_on: date | None = None
    regular_apr: Decimal | None = None
    maximum_months: int = 120


@dataclass(frozen=True, slots=True)
class OfferComparison:
    baseline: PayoffProjection
    offer: PayoffProjection
    fees: Decimal
    financed_balance: Decimal
    offer_cost: Decimal
    savings: Decimal | None
    break_even_date: date | None
    longer_payoff: bool


def compare_offer(debt: ProjectionDebt, *, start_date: date, spec: OfferSpec) -> OfferComparison:
    for value in (spec.annual_percentage_rate, spec.regular_apr, spec.fee_percent):
        if value is not None and (
            not value.is_finite()
            or not ZERO <= value < 1000
            or value != value.quantize(Decimal("0.0001"))
        ):
            raise ValidationError("Offer rates must be between 0 and 999.9999 percent.")
    _amount(spec.monthly_payment, "Monthly payment")
    _amount(spec.fixed_fee, "Fixed fees")
    if spec.monthly_payment <= 0 or not 1 <= spec.maximum_months <= 480:
        raise ValidationError("Use a positive monthly payment and a horizon of 1-480 months.")
    if (spec.expires_on is None) != (spec.regular_apr is None) or (
        spec.expires_on is not None and spec.expires_on < start_date
    ):
        raise ValidationError(
            "A promotional offer requires a future deadline and its APR afterward."
        )
    fees = money(debt.opening_balance * spec.fee_percent / 100 + spec.fixed_fee)
    financed = money(debt.opening_balance + (fees if spec.finance_fees else ZERO))
    promotion = (
        ProjectionPromotion(
            "introductory",
            start_date,
            spec.expires_on,
            spec.annual_percentage_rate,
            spec.regular_apr,
        )
        if spec.expires_on is not None and spec.regular_apr is not None
        else None
    )
    candidate = ProjectionDebt(
        debt.identifier,
        debt.name,
        financed,
        (
            ProjectionTerms(
                start_date,
                spec.annual_percentage_rate,
                DebtTermsRevision.InterestMethod.MONTHLY,
                DebtTermsRevision.DayCountBasis.ACTUAL_365,
                spec.monthly_payment,
            ),
        ),
        promotion=promotion,
    )
    baseline = project_debt_payoff(
        (debt,),
        strategy=PayoffStrategy.MINIMUM_ONLY,
        monthly_extra=ZERO,
        start_date=start_date,
        max_months=spec.maximum_months,
    )
    offer = project_debt_payoff(
        (candidate,),
        strategy=PayoffStrategy.MINIMUM_ONLY,
        monthly_extra=ZERO,
        start_date=start_date,
        max_months=spec.maximum_months,
    )
    comparable = baseline.paid_off and offer.paid_off
    savings = money(baseline.total_interest - offer.total_interest - fees) if comparable else None
    break_even = None
    if comparable and savings is not None and savings >= 0:
        baseline_cost = ZERO
        offer_cost = fees
        last_loss = start_date if fees > 0 else None
        dates = []
        for index in range(max(baseline.months, offer.months)):
            if index < len(baseline.cycles):
                baseline_cost += sum(
                    (payment.interest for payment in baseline.cycles[index].payments), ZERO
                )
            if index < len(offer.cycles):
                offer_cost += sum(
                    (payment.interest for payment in offer.cycles[index].payments), ZERO
                )
            current_date = _add_months(start_date, index + 1)
            dates.append(current_date)
            if baseline_cost < offer_cost:
                last_loss = current_date
        break_even = next(
            (value for value in dates if last_loss is None or value > last_loss), None
        )
        if last_loss is None:
            break_even = start_date
    return OfferComparison(
        baseline,
        offer,
        fees,
        financed,
        money(offer.total_interest + fees),
        savings,
        break_even,
        bool(
            comparable
            and offer.payoff_date
            and baseline.payoff_date
            and offer.payoff_date > baseline.payoff_date
        ),
    )


@dataclass(frozen=True, slots=True)
class ProgressRow:
    debt: DebtAccount
    principal_paid: Decimal
    interest_charged: Decimal
    fees_charged: Decimal
    statement_count: int
    stale_statement: bool
    paid_off: bool
    net_reduction: Decimal | None
    milestone: str
    payment_warning: bool


def debt_progress(household: Household, *, today: date) -> tuple[ProgressRow, ...]:
    rows = []
    openings = {
        event.entity_id: event.after_payload.get("opening_balance")
        for event in AuditEvent.objects.filter(
            household=household, action="debt.account_created", entity_type="debt_account"
        ).order_by("-sequence")
    }
    for debt in DebtAccount.objects.filter(household=household).order_by("name"):
        statements = tuple(
            DebtStatement.objects.filter(
                debt=debt, superseded_by__isnull=True, statement_date__lte=today
            )
        )
        try:
            opening = _money(Decimal(str(openings.get(str(debt.pk)))), "Opening balance")
        except (InvalidOperation, ValidationError):
            opening = None
        reduction = money(opening - debt.current_balance) if opening is not None else None
        milestone = "Building progress"
        if debt.current_balance == 0:
            milestone = "Balance cleared"
        elif reduction is not None and reduction < 0:
            milestone = "Balance increased since added"
        elif opening is not None and opening > 0 and reduction is not None:
            for threshold in (75, 50, 25):
                if reduction * 100 >= opening * threshold:
                    milestone = f"Balance down at least {threshold}%"
                    break
        terms = current_debt_terms(debt, on_date=today)
        monthly_interest = debt.current_balance * effective_apr(debt, on_date=today) / 1200
        rows.append(
            ProgressRow(
                debt,
                money(
                    sum(
                        (item.principal_paid + item.extra_principal_paid for item in statements),
                        ZERO,
                    )
                ),
                money(sum((item.interest_charged for item in statements), ZERO)),
                money(sum((item.fees_charged for item in statements), ZERO)),
                len(statements),
                bool(
                    debt.is_active
                    and debt.current_balance > 0
                    and (
                        debt.last_reconciled_on is None
                        or (today - debt.last_reconciled_on).days > 45
                    )
                ),
                debt.current_balance == 0,
                reduction,
                milestone,
                bool(
                    debt.is_active
                    and debt.current_balance > 0
                    and debt.debt_type != DebtAccount.DebtType.MORTGAGE
                    and terms.minimum_payment + terms.recurring_extra_payment <= monthly_interest
                ),
            )
        )
    return tuple(rows)
