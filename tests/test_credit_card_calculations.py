from decimal import Decimal

import pytest

from spending.services.credit_cards import allocate_card_payment


def test_golden_case_e_reserved_purchase_payment_is_not_new_debt_payoff() -> None:
    allocation = allocate_card_payment(
        payment=Decimal("75.00"), opening_payment_reserve=Decimal("75.00")
    )

    assert allocation.reserved_purchase_settlement == Decimal("75.00")
    assert allocation.current_income_funded_debt_payoff == Decimal("0.00")
    assert allocation.closing_payment_reserve == Decimal("0.00")


@pytest.mark.parametrize(
    ("payment", "expected_settlement", "expected_payoff"),
    [
        ("175.00", "75.00", "100.00"),
        ("125.00", "75.00", "50.00"),
    ],
)
def test_golden_case_f_payment_allocates_reserve_before_old_debt(
    payment: str, expected_settlement: str, expected_payoff: str
) -> None:
    allocation = allocate_card_payment(
        payment=Decimal(payment), opening_payment_reserve=Decimal("75.00")
    )

    assert allocation.reserved_purchase_settlement == Decimal(expected_settlement)
    assert allocation.current_income_funded_debt_payoff == Decimal(expected_payoff)
    assert allocation.closing_payment_reserve == Decimal("0.00")


def test_card_allocation_rejects_negative_values() -> None:
    with pytest.raises(ValueError, match="cannot be negative"):
        allocate_card_payment(payment=Decimal("-1.00"), opening_payment_reserve=Decimal("0"))
