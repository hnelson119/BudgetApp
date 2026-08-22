"""Credit-card cash-flow allocation rules."""

from dataclasses import dataclass
from decimal import Decimal

from budgets.services.calculations import money


@dataclass(frozen=True, slots=True)
class CardPaymentAllocation:
    payment: Decimal
    reserved_purchase_settlement: Decimal
    current_income_funded_debt_payoff: Decimal
    closing_payment_reserve: Decimal


def allocate_card_payment(
    *, payment: Decimal, opening_payment_reserve: Decimal
) -> CardPaymentAllocation:
    """Split a payment without counting purchases as spending a second time."""

    payment = money(payment)
    opening_payment_reserve = money(opening_payment_reserve)
    if payment < 0 or opening_payment_reserve < 0:
        raise ValueError("Payment and reserve values cannot be negative.")

    reserve_settlement = min(payment, opening_payment_reserve)
    debt_payoff = payment - reserve_settlement
    return CardPaymentAllocation(
        payment=payment,
        reserved_purchase_settlement=money(reserve_settlement),
        current_income_funded_debt_payoff=money(debt_payoff),
        closing_payment_reserve=money(opening_payment_reserve - reserve_settlement),
    )
