from decimal import Decimal

from budgets.services.calculations import (
    PeriodActuals,
    PeriodPlan,
    closing_household_reserve,
    money,
    spending_remaining,
)


def test_golden_case_a_basic_paycheck_period() -> None:
    plan = PeriodPlan(
        planned_income=money("2840.00"),
        planned_fixed_expenses=money("1926.50"),
        current_income_funded_required_debt=money("0"),
        scheduled_goal_contributions=money("350.00"),
        safety_buffer=money("0"),
        variable_spending_budget=money("420.00"),
    )
    actuals = PeriodActuals(
        actual_income_received=money("2840.00"),
        actual_fixed_expenses=money("1926.50"),
        current_income_funded_debt_payments=money("0"),
        actual_goal_contributions=money("350.00"),
        actual_variable_spending=money("133.60"),
    )

    assert plan.allocatable_amount() == Decimal("563.50")
    assert plan.unallocated_excess() == Decimal("143.50")
    remaining = spending_remaining(plan.variable_spending_budget, actuals.actual_variable_spending)
    assert remaining == Decimal("286.40")
    assert actuals.closing_surplus() == Decimal("429.90")
    assert closing_household_reserve(
        opening_reserve=money("0"), period_closing_surplus=actuals.closing_surplus()
    ) == Decimal("429.90")


def test_golden_case_b_existing_reserve_carries_forward_separately() -> None:
    assert closing_household_reserve(
        opening_reserve=money("500.00"),
        period_closing_surplus=money("429.90"),
    ) == Decimal("929.90")


def test_golden_case_c_explicit_reserve_allocation_reduces_reserve() -> None:
    assert closing_household_reserve(
        opening_reserve=money("929.90"),
        period_closing_surplus=money("0"),
        explicit_reserve_allocations_out=money("400.00"),
    ) == Decimal("529.90")


def test_golden_case_n_shortfall_is_not_auto_reallocated() -> None:
    plan = PeriodPlan(
        planned_income=money("1500.00"),
        planned_fixed_expenses=money("1400.00"),
        current_income_funded_required_debt=money("0"),
        scheduled_goal_contributions=money("200.00"),
        safety_buffer=money("0"),
        variable_spending_budget=money("300.00"),
    )

    assert plan.allocatable_amount() == Decimal("-100.00")
    assert plan.unallocated_excess() == Decimal("-400.00")


def test_money_uses_half_up_rounding() -> None:
    assert money("1.005") == Decimal("1.01")
