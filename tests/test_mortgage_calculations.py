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


@pytest.mark.parametrize(
    ("monthly", "principal_interest", "installments", "message"),
    (
        (Decimal("0.00"), Decimal("0.00"), (), "must be positive"),
        (Decimal("100.00"), Decimal("50.00"), (), "positive amounts"),
        (
            Decimal("100.00"),
            Decimal("101.00"),
            (Decimal("100.00"),),
            "within the monthly obligation",
        ),
    ),
)
def test_mortgage_obligation_rejects_invalid_components(
    monthly: Decimal,
    principal_interest: Decimal,
    installments: tuple[Decimal, ...],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        build_mortgage_obligation(
            monthly_obligation=monthly,
            principal_and_interest=principal_interest,
            installments=installments,
        )
