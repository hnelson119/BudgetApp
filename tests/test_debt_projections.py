from __future__ import annotations

from dataclasses import replace
from datetime import date
from decimal import Decimal

import pytest
from django.core.exceptions import ValidationError

from debts.models import DebtTermsRevision
from debts.services import (
    PayoffStrategy,
    ProjectionDebt,
    ProjectionTerms,
    compare_payoff_strategies,
    project_debt_payoff,
)


def _terms(
    *,
    effective_from: date = date(2026, 1, 1),
    apr: str = "0",
    minimum: str = "50.00",
    extra: str = "0.00",
    priority: int = 100,
    method: str = DebtTermsRevision.InterestMethod.MONTHLY,
    basis: str = DebtTermsRevision.DayCountBasis.ACTUAL_365,
) -> ProjectionTerms:
    return ProjectionTerms(
        effective_from=effective_from,
        annual_percentage_rate=Decimal(apr),
        interest_method=method,
        day_count_basis=basis,
        minimum_payment=Decimal(minimum),
        recurring_extra_payment=Decimal(extra),
        custom_priority=priority,
    )


def _debt(
    identifier: str,
    name: str,
    balance: str,
    *terms: ProjectionTerms,
) -> ProjectionDebt:
    return ProjectionDebt(
        identifier=identifier,
        name=name,
        opening_balance=Decimal(balance),
        terms=terms or (_terms(),),
    )


def test_monthly_projection_posts_interest_before_payment() -> None:
    projection = project_debt_payoff(
        (_debt("loan", "Loan", "1200.00", _terms(apr="12", minimum="112.00")),),
        strategy=PayoffStrategy.MINIMUM_ONLY,
        monthly_extra=Decimal("0.00"),
        start_date=date(2026, 1, 1),
        max_months=1,
    )

    payment = projection.cycles[0].payments[0]
    assert payment.opening_balance == Decimal("1200.00")
    assert payment.interest == Decimal("12.00")
    assert payment.minimum_payment == Decimal("112.00")
    assert payment.closing_balance == Decimal("1100.00")
    assert projection.total_interest == Decimal("12.00")
    assert projection.paid_off is False
    assert payment.total_payment == Decimal("112.00")
    assert projection.cycles[0].total_payment == Decimal("112.00")


def test_daily_projection_uses_actual_days_and_configured_basis() -> None:
    projection = project_debt_payoff(
        (
            _debt(
                "daily",
                "Daily loan",
                "1000.00",
                _terms(
                    apr="36.5",
                    minimum="0.00",
                    method=DebtTermsRevision.InterestMethod.DAILY,
                ),
            ),
        ),
        strategy=PayoffStrategy.MINIMUM_ONLY,
        monthly_extra=Decimal("0.00"),
        start_date=date(2026, 1, 1),
        max_months=1,
    )

    assert projection.cycles[0].payment_date == date(2026, 2, 1)
    assert projection.cycles[0].payments[0].interest == Decimal("31.00")
    assert projection.debts[0].remaining_balance == Decimal("1031.00")


def test_daily_actual_360_and_month_end_dates_are_deterministic() -> None:
    projection = project_debt_payoff(
        (
            _debt(
                "daily-360",
                "Daily 360 loan",
                "1000.00",
                _terms(
                    apr="36",
                    minimum="0.00",
                    method=DebtTermsRevision.InterestMethod.DAILY,
                    basis=DebtTermsRevision.DayCountBasis.ACTUAL_360,
                ),
            ),
        ),
        strategy=PayoffStrategy.MINIMUM_ONLY,
        monthly_extra=Decimal("0.00"),
        start_date=date(2026, 1, 31),
        max_months=2,
    )

    assert projection.cycles[0].payment_date == date(2026, 2, 28)
    assert projection.cycles[0].payments[0].interest == Decimal("28.00")
    assert projection.cycles[1].payment_date == date(2026, 3, 31)


def test_effective_dated_terms_change_future_projection_cycles() -> None:
    projection = project_debt_payoff(
        (
            _debt(
                "changing",
                "Changing APR",
                "1000.00",
                _terms(apr="0", minimum="0.00"),
                _terms(
                    effective_from=date(2026, 3, 1),
                    apr="12",
                    minimum="0.00",
                ),
            ),
        ),
        strategy=PayoffStrategy.MINIMUM_ONLY,
        monthly_extra=Decimal("0.00"),
        start_date=date(2026, 1, 1),
        max_months=2,
    )

    assert projection.cycles[0].payments[0].interest == Decimal("0.00")
    assert projection.cycles[1].payments[0].interest == Decimal("10.00")


def test_snowball_and_avalanche_direct_extra_to_different_debts() -> None:
    debts = (
        _debt("small", "Small low-rate", "500.00", _terms(apr="5", minimum="50.00")),
        _debt("large", "Large high-rate", "1000.00", _terms(apr="20", minimum="50.00")),
    )
    snowball = project_debt_payoff(
        debts,
        strategy=PayoffStrategy.SNOWBALL,
        monthly_extra=Decimal("100.00"),
        start_date=date(2026, 1, 1),
        max_months=1,
    )
    avalanche = project_debt_payoff(
        debts,
        strategy=PayoffStrategy.AVALANCHE,
        monthly_extra=Decimal("100.00"),
        start_date=date(2026, 1, 1),
        max_months=1,
    )

    snowball_payments = {value.debt_identifier: value for value in snowball.cycles[0].payments}
    avalanche_payments = {value.debt_identifier: value for value in avalanche.cycles[0].payments}
    assert snowball_payments["small"].strategy_extra_payment == Decimal("100.00")
    assert snowball_payments["large"].strategy_extra_payment == Decimal("0.00")
    assert avalanche_payments["large"].strategy_extra_payment == Decimal("100.00")
    assert avalanche_payments["small"].strategy_extra_payment == Decimal("0.00")


def test_freed_required_payment_rolls_beginning_next_strategy_cycle() -> None:
    debts = (
        _debt("first", "First", "50.00", _terms(minimum="50.00", priority=1)),
        _debt("second", "Second", "500.00", _terms(minimum="50.00", priority=2)),
    )
    custom = project_debt_payoff(
        debts,
        strategy=PayoffStrategy.CUSTOM,
        monthly_extra=Decimal("0.00"),
        start_date=date(2026, 1, 1),
        max_months=2,
    )
    minimum_only = project_debt_payoff(
        debts,
        strategy=PayoffStrategy.MINIMUM_ONLY,
        monthly_extra=Decimal("0.00"),
        start_date=date(2026, 1, 1),
        max_months=2,
    )

    custom_second_cycle = {value.debt_identifier: value for value in custom.cycles[1].payments}
    minimum_second_cycle = {
        value.debt_identifier: value for value in minimum_only.cycles[1].payments
    }
    assert custom_second_cycle["second"].minimum_payment == Decimal("50.00")
    assert custom_second_cycle["second"].strategy_extra_payment == Decimal("50.00")
    assert minimum_second_cycle["second"].strategy_extra_payment == Decimal("0.00")


def test_strategy_comparison_reports_payoff_date_time_and_interest_savings() -> None:
    debts = (
        _debt("first", "First", "50.00", _terms(minimum="50.00", priority=1)),
        _debt("second", "Second", "500.00", _terms(minimum="50.00", priority=2)),
    )
    comparison = compare_payoff_strategies(
        debts,
        monthly_extra=Decimal("0.00"),
        start_date=date(2026, 1, 1),
    )

    rows = {row.strategy: row for row in comparison.strategies}
    assert comparison.baseline.months == 10
    assert rows[PayoffStrategy.MINIMUM_ONLY].months_saved == 0
    assert rows[PayoffStrategy.SNOWBALL].projection.months == 6
    assert rows[PayoffStrategy.SNOWBALL].months_saved == 4
    assert rows[PayoffStrategy.SNOWBALL].interest_saved == Decimal("0.00")
    assert rows[PayoffStrategy.CUSTOM].projection.payoff_date == date(2026, 7, 1)


def test_projection_handles_empty_and_beyond_horizon_comparisons() -> None:
    empty = project_debt_payoff(
        (),
        strategy=PayoffStrategy.MINIMUM_ONLY,
        monthly_extra=Decimal("0.00"),
        start_date=date(2026, 1, 1),
    )
    assert empty.paid_off is True
    assert empty.payoff_date == date(2026, 1, 1)
    assert empty.months == 0

    comparison = compare_payoff_strategies(
        (_debt("stalled", "Stalled", "100.00", _terms(minimum="0.00")),),
        monthly_extra=Decimal("0.00"),
        start_date=date(2026, 1, 1),
        max_months=1,
    )
    assert comparison.baseline.paid_off is False
    for row in comparison.strategies:
        assert row.months_saved is None
        assert row.interest_saved is None


@pytest.mark.parametrize(
    ("terms", "message"),
    (
        (replace(_terms(), annual_percentage_rate=Decimal("-1")), "APR"),
        (replace(_terms(), annual_percentage_rate=Decimal("NaN")), "APR"),
        (replace(_terms(), interest_method="invalid"), "interest method"),
        (replace(_terms(), day_count_basis="invalid"), "day-count basis"),
        (replace(_terms(), custom_priority=0), "priority"),
        (replace(_terms(), minimum_payment=Decimal("1.001")), "two decimals"),
        (replace(_terms(), recurring_extra_payment=Decimal("-1.00")), "nonnegative"),
    ),
)
def test_projection_rejects_invalid_term_assumptions(
    terms: ProjectionTerms,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        project_debt_payoff(
            (_debt("invalid", "Invalid", "100.00", terms),),
            strategy=PayoffStrategy.MINIMUM_ONLY,
            monthly_extra=Decimal("0.00"),
            start_date=date(2026, 1, 1),
        )


@pytest.mark.parametrize(
    ("debt", "message"),
    (
        (_debt(" ", "Debt", "1.00"), "nonempty and unique"),
        (_debt("one", " ", "1.00"), "names are required"),
        (_debt("one", "Debt", "-1.00"), "nonnegative"),
        (
            _debt(
                "one",
                "Debt",
                "1.00",
                _terms(),
                _terms(apr="1"),
            ),
            "term dates must be unique",
        ),
    ),
)
def test_projection_rejects_invalid_debt_identity_balance_and_term_dates(
    debt: ProjectionDebt,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        project_debt_payoff(
            (debt,),
            strategy=PayoffStrategy.MINIMUM_ONLY,
            monthly_extra=Decimal("0.00"),
            start_date=date(2026, 1, 1),
        )


def test_projection_rejects_invalid_strategy_and_too_many_debts() -> None:
    with pytest.raises(ValidationError, match="strategy is invalid"):
        project_debt_payoff(
            (),
            strategy="invalid",  # type: ignore[arg-type]
            monthly_extra=Decimal("0.00"),
            start_date=date(2026, 1, 1),
        )
    with pytest.raises(ValidationError, match="more than 100"):
        project_debt_payoff(
            tuple(_debt(str(index), f"Debt {index}", "1.00") for index in range(101)),
            strategy=PayoffStrategy.MINIMUM_ONLY,
            monthly_extra=Decimal("0.00"),
            start_date=date(2026, 1, 1),
        )


@pytest.mark.parametrize(
    ("debts", "extra", "max_months", "message"),
    (
        (
            (_debt("same", "One", "1.00"), _debt("same", "Two", "1.00")),
            Decimal("0.00"),
            12,
            "unique",
        ),
        (
            (_debt("future", "Future", "1.00", _terms(effective_from=date(2027, 1, 1))),),
            Decimal("0.00"),
            12,
            "effective",
        ),
        ((_debt("one", "One", "1.00"),), Decimal("-1.00"), 12, "nonnegative"),
        ((_debt("one", "One", "1.00"),), Decimal("0.00"), 0, "between"),
    ),
)
def test_projection_validation_fails_closed(
    debts: tuple[ProjectionDebt, ...],
    extra: Decimal,
    max_months: int,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        project_debt_payoff(
            debts,
            strategy=PayoffStrategy.SNOWBALL,
            monthly_extra=extra,
            start_date=date(2026, 1, 1),
            max_months=max_months,
        )
