"""Mortgage cash-flow validation separate from loan amortization."""

from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal

from budgets.services.calculations import money


@dataclass(frozen=True, slots=True)
class MortgageObligation:
    monthly_obligation: Decimal
    principal_and_interest: Decimal
    escrow: Decimal
    installments: tuple[Decimal, ...]


def build_mortgage_obligation(
    *,
    monthly_obligation: Decimal,
    principal_and_interest: Decimal,
    installments: Iterable[Decimal],
) -> MortgageObligation:
    monthly_obligation = money(monthly_obligation)
    principal_and_interest = money(principal_and_interest)
    normalized_installments = tuple(money(value) for value in installments)

    if monthly_obligation <= 0:
        raise ValueError("The monthly mortgage obligation must be positive.")
    if not normalized_installments or any(value <= 0 for value in normalized_installments):
        raise ValueError("Mortgage installments must contain positive amounts.")
    if principal_and_interest < 0 or principal_and_interest > monthly_obligation:
        raise ValueError("Principal and interest must be within the monthly obligation.")
    if money(sum(normalized_installments, Decimal("0.00"))) != monthly_obligation:
        raise ValueError("Mortgage installments must total the monthly obligation exactly.")

    return MortgageObligation(
        monthly_obligation=monthly_obligation,
        principal_and_interest=principal_and_interest,
        escrow=money(monthly_obligation - principal_and_interest),
        installments=normalized_installments,
    )
