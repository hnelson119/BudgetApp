"""Pure paycheck-period calculations.

These functions deliberately contain no database access. Keeping the arithmetic
pure makes the formulas easy to audit and protects the UI from inventing its own
slightly different totals.
"""

from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal

MONEY_QUANTUM = Decimal("0.01")


def money(value: Decimal | str | int) -> Decimal:
    """Return a currency value rounded to cents using one application-wide rule."""

    return Decimal(str(value)).quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


@dataclass(frozen=True, slots=True)
class PeriodPlan:
    planned_income: Decimal
    planned_fixed_expenses: Decimal
    current_income_funded_required_debt: Decimal
    scheduled_goal_contributions: Decimal
    safety_buffer: Decimal
    variable_spending_budget: Decimal

    def allocatable_amount(self) -> Decimal:
        return money(
            self.planned_income
            - self.planned_fixed_expenses
            - self.current_income_funded_required_debt
            - self.scheduled_goal_contributions
            - self.safety_buffer
        )

    def unallocated_excess(self) -> Decimal:
        return money(self.allocatable_amount() - self.variable_spending_budget)


@dataclass(frozen=True, slots=True)
class PeriodActuals:
    actual_income_received: Decimal
    actual_fixed_expenses: Decimal
    current_income_funded_debt_payments: Decimal
    actual_goal_contributions: Decimal
    actual_variable_spending: Decimal
    safety_buffer_used: Decimal = Decimal("0.00")

    def closing_surplus(self) -> Decimal:
        return money(
            self.actual_income_received
            - self.actual_fixed_expenses
            - self.current_income_funded_debt_payments
            - self.actual_goal_contributions
            - self.actual_variable_spending
            - self.safety_buffer_used
        )


def spending_remaining(variable_spending_budget: Decimal, actual_spending: Decimal) -> Decimal:
    return money(variable_spending_budget - actual_spending)


def closing_household_reserve(
    *,
    opening_reserve: Decimal,
    period_closing_surplus: Decimal,
    explicit_reserve_allocations_out: Decimal = Decimal("0.00"),
) -> Decimal:
    return money(opening_reserve + period_closing_surplus - explicit_reserve_allocations_out)
