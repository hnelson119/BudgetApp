from decimal import Decimal

import pytest

from debts.services.mortgage import build_mortgage_obligation


def test_golden_case_h_twice_monthly_mortgage_separates_escrow() -> None:
    mortgage = build_mortgage_obligation(
        monthly_obligation=Decimal("1350.00"),
        principal_and_interest=Decimal("1100.00"),
        installments=(Decimal("675.00"), Decimal("675.00")),
    )

    assert mortgage.installments == (Decimal("675.00"), Decimal("675.00"))
    assert mortgage.principal_and_interest == Decimal("1100.00")
    assert mortgage.escrow == Decimal("250.00")


def test_mortgage_installments_must_equal_obligation() -> None:
    with pytest.raises(ValueError, match="must total"):
        build_mortgage_obligation(
            monthly_obligation=Decimal("1350.00"),
            principal_and_interest=Decimal("1100.00"),
            installments=(Decimal("600.00"), Decimal("675.00")),
        )
