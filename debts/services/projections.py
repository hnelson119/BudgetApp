from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from enum import StrEnum

from django.core.exceptions import ValidationError
from django.db.models import F

from budgets.services.calculations import money
from debts.models import (
    DebtAccount,
    DebtTermsRevision,
    MortgagePaymentComponent,
    MortgagePaymentPlan,
)
from schedules.models import Occurrence

_MAX_DEBTS = 100
_MAX_MONTHS = 1_200


class PayoffStrategy(StrEnum):
    MINIMUM_ONLY = "minimum_only"
    SNOWBALL = "snowball"
    AVALANCHE = "avalanche"
    CUSTOM = "custom"


@dataclass(frozen=True, slots=True)
class ProjectionTerms:
    effective_from: date
    annual_percentage_rate: Decimal
    interest_method: str
    day_count_basis: str
    minimum_payment: Decimal
    recurring_extra_payment: Decimal = Decimal("0.00")
    custom_priority: int = 100


@dataclass(frozen=True, slots=True)
class ProjectionExtraPayment:
    effective_date: date
    amount: Decimal


@dataclass(frozen=True, slots=True)
class ProjectionDebt:
    identifier: str
    name: str
    opening_balance: Decimal
    terms: tuple[ProjectionTerms, ...]
    one_time_extra_payments: tuple[ProjectionExtraPayment, ...] = ()


@dataclass(frozen=True, slots=True)
class ProjectionPayment:
    debt_identifier: str
    opening_balance: Decimal
    interest: Decimal
    minimum_payment: Decimal
    scheduled_extra_payment: Decimal
    one_time_extra_payment: Decimal
    strategy_extra_payment: Decimal
    closing_balance: Decimal

    @property
    def total_payment(self) -> Decimal:
        return money(
            self.minimum_payment
            + self.scheduled_extra_payment
            + self.one_time_extra_payment
            + self.strategy_extra_payment
        )


@dataclass(frozen=True, slots=True)
class ProjectionCycle:
    payment_date: date
    payments: tuple[ProjectionPayment, ...]

    @property
    def total_payment(self) -> Decimal:
        return money(sum((payment.total_payment for payment in self.payments), Decimal("0.00")))


@dataclass(frozen=True, slots=True)
class DebtProjectionResult:
    debt_identifier: str
    name: str
    opening_balance: Decimal
    payoff_date: date | None
    total_interest: Decimal
    total_paid: Decimal
    remaining_balance: Decimal


@dataclass(frozen=True, slots=True)
class PayoffProjection:
    strategy: PayoffStrategy
    start_date: date
    payoff_date: date | None
    months: int
    total_interest: Decimal
    total_paid: Decimal
    paid_off: bool
    debts: tuple[DebtProjectionResult, ...]
    cycles: tuple[ProjectionCycle, ...]


@dataclass(frozen=True, slots=True)
class StrategyComparison:
    strategy: PayoffStrategy
    projection: PayoffProjection
    months_saved: int | None
    interest_saved: Decimal | None


@dataclass(frozen=True, slots=True)
class PayoffComparison:
    baseline: PayoffProjection
    strategies: tuple[StrategyComparison, ...]


@dataclass(slots=True)
class _DebtState:
    debt: ProjectionDebt
    balance: Decimal
    total_interest: Decimal = Decimal("0.00")
    total_paid: Decimal = Decimal("0.00")
    payoff_date: date | None = None


@dataclass(slots=True)
class _CyclePayment:
    opening_balance: Decimal
    interest: Decimal
    minimum_payment: Decimal = Decimal("0.00")
    scheduled_extra_payment: Decimal = Decimal("0.00")
    one_time_extra_payment: Decimal = Decimal("0.00")
    strategy_extra_payment: Decimal = Decimal("0.00")


def _add_months(value: date, months: int) -> date:
    month_index = value.month - 1 + months
    year = value.year + month_index // 12
    month = month_index % 12 + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return date(year, month, day)


def _validated_money(value: Decimal, label: str) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ValidationError(f"{label} must use a finite Decimal value.")
    normalized = money(value)
    if normalized != value or normalized < 0:
        raise ValidationError(f"{label} must be nonnegative with at most two decimals.")
    return normalized


def _validate_terms(terms: ProjectionTerms) -> ProjectionTerms:
    apr = terms.annual_percentage_rate
    if not isinstance(apr, Decimal) or not apr.is_finite() or not Decimal("0") <= apr < 1000:
        raise ValidationError("Projection APR must be between 0 and 999.9999 percent.")
    if terms.interest_method not in DebtTermsRevision.InterestMethod.values:
        raise ValidationError("Projection interest method is invalid.")
    if terms.day_count_basis not in DebtTermsRevision.DayCountBasis.values:
        raise ValidationError("Projection day-count basis is invalid.")
    if terms.custom_priority < 1:
        raise ValidationError("Projection custom priority must be positive.")
    return ProjectionTerms(
        effective_from=terms.effective_from,
        annual_percentage_rate=apr,
        interest_method=terms.interest_method,
        day_count_basis=terms.day_count_basis,
        minimum_payment=_validated_money(terms.minimum_payment, "Projection minimum payment"),
        recurring_extra_payment=_validated_money(
            terms.recurring_extra_payment,
            "Projection recurring extra payment",
        ),
        custom_priority=terms.custom_priority,
    )


def _validate_debts(
    debts: tuple[ProjectionDebt, ...],
    *,
    start_date: date,
) -> tuple[ProjectionDebt, ...]:
    if len(debts) > _MAX_DEBTS:
        raise ValidationError(f"A projection cannot contain more than {_MAX_DEBTS} debts.")
    identifiers: set[str] = set()
    normalized: list[ProjectionDebt] = []
    for debt in debts:
        identifier = debt.identifier.strip()
        name = debt.name.strip()
        if not identifier or identifier in identifiers:
            raise ValidationError("Projection debt identifiers must be nonempty and unique.")
        if not name:
            raise ValidationError("Projection debt names are required.")
        identifiers.add(identifier)
        terms = tuple(
            sorted((_validate_terms(value) for value in debt.terms), key=lambda x: x.effective_from)
        )
        if not terms or terms[0].effective_from > start_date:
            raise ValidationError("Each debt needs terms effective on the projection start date.")
        if len({value.effective_from for value in terms}) != len(terms):
            raise ValidationError("Projection debt term dates must be unique.")
        one_time_extras = tuple(
            sorted(
                (
                    ProjectionExtraPayment(
                        effective_date=value.effective_date,
                        amount=_validated_money(value.amount, "Projection one-time extra payment"),
                    )
                    for value in debt.one_time_extra_payments
                ),
                key=lambda value: value.effective_date,
            )
        )
        normalized.append(
            ProjectionDebt(
                identifier=identifier,
                name=name,
                opening_balance=_validated_money(
                    debt.opening_balance, "Projection opening balance"
                ),
                terms=terms,
                one_time_extra_payments=one_time_extras,
            )
        )
    return tuple(normalized)


def _terms_on(debt: ProjectionDebt, on_date: date) -> ProjectionTerms:
    applicable = tuple(terms for terms in debt.terms if terms.effective_from <= on_date)
    if not applicable:
        raise ValidationError("The debt has no terms effective for this projection cycle.")
    return applicable[-1]


def _cycle_interest(
    balance: Decimal,
    terms: ProjectionTerms,
    *,
    previous_date: date,
    payment_date: date,
) -> Decimal:
    if terms.interest_method == DebtTermsRevision.InterestMethod.MONTHLY:
        return money(balance * terms.annual_percentage_rate / Decimal("1200"))
    basis = (
        Decimal("360")
        if terms.day_count_basis == DebtTermsRevision.DayCountBasis.ACTUAL_360
        else Decimal("365")
    )
    days = Decimal((payment_date - previous_date).days)
    return money(balance * terms.annual_percentage_rate / Decimal("100") * days / basis)


def _strategy_order(
    states: tuple[_DebtState, ...],
    strategy: PayoffStrategy,
    on_date: date,
) -> tuple[_DebtState, ...]:
    active = tuple(state for state in states if state.balance > 0)
    if strategy == PayoffStrategy.SNOWBALL:
        return tuple(sorted(active, key=lambda state: (state.balance, state.debt.name.casefold())))
    if strategy == PayoffStrategy.AVALANCHE:
        return tuple(
            sorted(
                active,
                key=lambda state: (
                    -_terms_on(state.debt, on_date).annual_percentage_rate,
                    state.balance,
                    state.debt.name.casefold(),
                ),
            )
        )
    return tuple(
        sorted(
            active,
            key=lambda state: (
                _terms_on(state.debt, on_date).custom_priority,
                state.debt.name.casefold(),
            ),
        )
    )


def project_debt_payoff(
    debts: tuple[ProjectionDebt, ...],
    *,
    strategy: PayoffStrategy,
    monthly_extra: Decimal,
    start_date: date,
    max_months: int = _MAX_MONTHS,
) -> PayoffProjection:
    try:
        strategy = PayoffStrategy(strategy)
    except ValueError as error:
        raise ValidationError("Payoff strategy is invalid.") from error
    if not 1 <= max_months <= _MAX_MONTHS:
        raise ValidationError(f"Projection length must be between 1 and {_MAX_MONTHS} months.")
    normalized_extra = _validated_money(monthly_extra, "Projection monthly extra payment")
    normalized_debts = _validate_debts(debts, start_date=start_date)
    states = tuple(_DebtState(debt=debt, balance=debt.opening_balance) for debt in normalized_debts)
    cycles: list[ProjectionCycle] = []
    rollover = Decimal("0.00")

    for month_number in range(1, max_months + 1):
        if all(state.balance == 0 for state in states):
            break
        previous_date = _add_months(start_date, month_number - 1)
        payment_date = _add_months(start_date, month_number)
        payments: dict[str, _CyclePayment] = {}
        payoff_candidates: list[tuple[_DebtState, ProjectionTerms]] = []

        for state in states:
            if state.balance == 0:
                continue
            terms = _terms_on(state.debt, payment_date)
            opening_balance = state.balance
            interest = _cycle_interest(
                opening_balance,
                terms,
                previous_date=previous_date,
                payment_date=payment_date,
            )
            state.balance = money(state.balance + interest)
            state.total_interest = money(state.total_interest + interest)
            minimum = min(terms.minimum_payment, state.balance)
            state.balance = money(state.balance - minimum)
            scheduled_extra = min(terms.recurring_extra_payment, state.balance)
            state.balance = money(state.balance - scheduled_extra)
            requested_one_time_extra = money(
                sum(
                    (
                        extra.amount
                        for extra in state.debt.one_time_extra_payments
                        if previous_date < extra.effective_date <= payment_date
                    ),
                    Decimal("0.00"),
                )
            )
            one_time_extra = min(requested_one_time_extra, state.balance)
            state.balance = money(state.balance - one_time_extra)
            state.total_paid = money(state.total_paid + minimum + scheduled_extra + one_time_extra)
            payments[state.debt.identifier] = _CyclePayment(
                opening_balance=opening_balance,
                interest=interest,
                minimum_payment=minimum,
                scheduled_extra_payment=scheduled_extra,
                one_time_extra_payment=one_time_extra,
            )
            if state.balance == 0:
                payoff_candidates.append((state, terms))

        if strategy != PayoffStrategy.MINIMUM_ONLY:
            available_extra = money(normalized_extra + rollover)
            for state in _strategy_order(states, strategy, payment_date):
                if available_extra == 0:
                    break
                extra = min(available_extra, state.balance)
                state.balance = money(state.balance - extra)
                state.total_paid = money(state.total_paid + extra)
                payments[state.debt.identifier].strategy_extra_payment = extra
                available_extra = money(available_extra - extra)
                if state.balance == 0:
                    payoff_candidates.append((state, _terms_on(state.debt, payment_date)))

        newly_paid: set[str] = set()
        for state, terms in payoff_candidates:
            if state.payoff_date is None and state.balance == 0:
                state.payoff_date = payment_date
                newly_paid.add(state.debt.identifier)
                if strategy != PayoffStrategy.MINIMUM_ONLY:
                    rollover = money(
                        rollover + terms.minimum_payment + terms.recurring_extra_payment
                    )

        cycle_rows = tuple(
            ProjectionPayment(
                debt_identifier=state.debt.identifier,
                opening_balance=payments[state.debt.identifier].opening_balance,
                interest=payments[state.debt.identifier].interest,
                minimum_payment=payments[state.debt.identifier].minimum_payment,
                scheduled_extra_payment=payments[state.debt.identifier].scheduled_extra_payment,
                one_time_extra_payment=payments[state.debt.identifier].one_time_extra_payment,
                strategy_extra_payment=payments[state.debt.identifier].strategy_extra_payment,
                closing_balance=state.balance,
            )
            for state in states
            if state.debt.identifier in payments
        )
        cycles.append(ProjectionCycle(payment_date=payment_date, payments=cycle_rows))

    paid_off = all(state.balance == 0 for state in states)
    payoff_date = max(
        (state.payoff_date for state in states if state.payoff_date is not None),
        default=start_date if not states else None,
    )
    debt_results = tuple(
        DebtProjectionResult(
            debt_identifier=state.debt.identifier,
            name=state.debt.name,
            opening_balance=state.debt.opening_balance,
            payoff_date=state.payoff_date,
            total_interest=state.total_interest,
            total_paid=state.total_paid,
            remaining_balance=state.balance,
        )
        for state in states
    )
    return PayoffProjection(
        strategy=strategy,
        start_date=start_date,
        payoff_date=payoff_date if paid_off else None,
        months=len(cycles),
        total_interest=money(sum((state.total_interest for state in states), Decimal("0.00"))),
        total_paid=money(sum((state.total_paid for state in states), Decimal("0.00"))),
        paid_off=paid_off,
        debts=debt_results,
        cycles=tuple(cycles),
    )


def compare_payoff_strategies(
    debts: tuple[ProjectionDebt, ...],
    *,
    monthly_extra: Decimal,
    start_date: date,
    max_months: int = _MAX_MONTHS,
) -> PayoffComparison:
    baseline = project_debt_payoff(
        debts,
        strategy=PayoffStrategy.MINIMUM_ONLY,
        monthly_extra=Decimal("0.00"),
        start_date=start_date,
        max_months=max_months,
    )
    rows: list[StrategyComparison] = [
        StrategyComparison(
            strategy=PayoffStrategy.MINIMUM_ONLY,
            projection=baseline,
            months_saved=0 if baseline.paid_off else None,
            interest_saved=Decimal("0.00") if baseline.paid_off else None,
        )
    ]
    for strategy in (
        PayoffStrategy.SNOWBALL,
        PayoffStrategy.AVALANCHE,
        PayoffStrategy.CUSTOM,
    ):
        projection = project_debt_payoff(
            debts,
            strategy=strategy,
            monthly_extra=monthly_extra,
            start_date=start_date,
            max_months=max_months,
        )
        comparable = baseline.paid_off and projection.paid_off
        rows.append(
            StrategyComparison(
                strategy=strategy,
                projection=projection,
                months_saved=(baseline.months - projection.months) if comparable else None,
                interest_saved=(
                    money(baseline.total_interest - projection.total_interest)
                    if comparable
                    else None
                ),
            )
        )
    return PayoffComparison(baseline=baseline, strategies=tuple(rows))


def projection_debts_from_accounts(
    debts: tuple[DebtAccount, ...],
) -> tuple[ProjectionDebt, ...]:
    projected: list[ProjectionDebt] = []
    for debt in debts:
        if not debt.is_active or debt.current_balance == 0:
            continue
        revisions = tuple(debt.terms_revisions.all().order_by("effective_from", "revision_number"))
        projection_terms = tuple(
            ProjectionTerms(
                effective_from=revision.effective_from,
                annual_percentage_rate=revision.annual_percentage_rate,
                interest_method=revision.interest_method,
                day_count_basis=revision.day_count_basis,
                minimum_payment=revision.minimum_payment,
                recurring_extra_payment=revision.recurring_extra_payment,
                custom_priority=revision.custom_priority,
            )
            for revision in revisions
        )
        one_time_extras: tuple[ProjectionExtraPayment, ...] = ()
        try:
            mortgage_plan = debt.mortgage_payment_plan
        except MortgagePaymentPlan.DoesNotExist:
            mortgage_plan = None
        if mortgage_plan is not None:
            mortgage_revisions = tuple(
                mortgage_plan.revisions.prefetch_related("components").order_by(
                    "effective_from", "revision_number"
                )
            )
            effective_dates = sorted(
                {value.effective_from for value in revisions}
                | {value.effective_from for value in mortgage_revisions}
            )
            mortgage_terms: list[ProjectionTerms] = []
            for effective_date in effective_dates:
                debt_terms = tuple(
                    value for value in revisions if value.effective_from <= effective_date
                )
                plan_revisions = tuple(
                    value for value in mortgage_revisions if value.effective_from <= effective_date
                )
                if not debt_terms:
                    continue
                current_terms = debt_terms[-1]
                if plan_revisions:
                    components = {
                        item.component_type: item.amount
                        for item in plan_revisions[-1].components.all()
                    }
                    minimum_payment = components[
                        MortgagePaymentComponent.ComponentType.PRINCIPAL_INTEREST
                    ]
                    recurring_extra = components[
                        MortgagePaymentComponent.ComponentType.RECURRING_EXTRA_PRINCIPAL
                    ]
                else:
                    minimum_payment = current_terms.minimum_payment
                    recurring_extra = current_terms.recurring_extra_payment
                mortgage_terms.append(
                    ProjectionTerms(
                        effective_from=effective_date,
                        annual_percentage_rate=current_terms.annual_percentage_rate,
                        interest_method=current_terms.interest_method,
                        day_count_basis=current_terms.day_count_basis,
                        minimum_payment=minimum_payment,
                        recurring_extra_payment=recurring_extra,
                        custom_priority=current_terms.custom_priority,
                    )
                )
            projection_terms = tuple(mortgage_terms)
            source_ids = {
                value.source_id
                for revision in mortgage_revisions
                for value in revision.installment_rules.all()
            }
            occurrences = Occurrence.objects.filter(
                source_id__in=source_ids,
                status__in=(
                    Occurrence.Status.SCHEDULED,
                    Occurrence.Status.MOVED,
                    Occurrence.Status.OVERRIDDEN,
                ),
                planned_amount__gt=F("generated_amount"),
            ).order_by("expected_date", "pk")
            one_time_extras = tuple(
                ProjectionExtraPayment(
                    effective_date=occurrence.expected_date,
                    amount=money(occurrence.planned_amount - occurrence.generated_amount),
                )
                for occurrence in occurrences
            )
        projected.append(
            ProjectionDebt(
                identifier=str(debt.pk),
                name=debt.name,
                opening_balance=debt.current_balance,
                terms=projection_terms,
                one_time_extra_payments=one_time_extras,
            )
        )
    return tuple(projected)
