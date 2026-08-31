from __future__ import annotations

from decimal import Decimal, InvalidOperation

from django.core.exceptions import ValidationError
from django.db import transaction

from audit.services import append_event
from budgets.models import VariableBudget
from households.models import Category
from households.services.access import require_household_membership
from identity.models import User
from periods.models import PayPeriod

_CENT = Decimal("0.01")


class _UncheckedBudgetVersion:
    pass


_UNCHECKED_BUDGET_VERSION = _UncheckedBudgetVersion()


def _money(value: Decimal) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ValidationError("Budget amounts must use finite Decimal values.")
    try:
        normalized = value.quantize(_CENT)
    except InvalidOperation as error:
        raise ValidationError("Budget amount is invalid.") from error
    if normalized != value or normalized < 0:
        raise ValidationError("Budget amounts must be nonnegative with at most two decimals.")
    return normalized


@transaction.atomic
def set_variable_budget(
    *,
    pay_period: PayPeriod,
    category: Category,
    planned_amount: Decimal,
    actor: User,
    request_id: str,
    notes: str = "",
    expected_version: str | _UncheckedBudgetVersion = _UNCHECKED_BUDGET_VERSION,
) -> VariableBudget:
    period = PayPeriod.objects.select_for_update().select_related("household").get(pk=pay_period.pk)
    require_household_membership(actor, period.household)
    locked_category = Category.objects.select_for_update().get(pk=category.pk)
    if locked_category.household_id != period.household_id:
        raise ValidationError("The category belongs to another household.")
    if locked_category.is_archived:
        raise ValidationError("Archived categories cannot receive new budget amounts.")
    if period.status == PayPeriod.Status.CLOSED:
        raise ValidationError("Reopen the closed paycheck period before changing its budget.")
    normalized = _money(planned_amount)
    existing = VariableBudget.objects.filter(
        pay_period=period,
        category=locked_category,
    ).first()
    if not isinstance(expected_version, _UncheckedBudgetVersion):
        current_version = existing.updated_at.isoformat() if existing is not None else ""
        if expected_version != current_version:
            raise ValidationError(
                "This category budget changed after the form was opened; refresh and try again."
            )
    before = None
    if existing is None:
        budget = VariableBudget(
            pay_period=period,
            category=locked_category,
            created_by=actor,
        )
        action = "budget.variable_created"
    else:
        budget = existing
        before = {"planned_amount": budget.planned_amount, "notes": budget.notes}
        action = "budget.variable_updated"
    budget.planned_amount = normalized
    budget.notes = notes.strip()
    budget.full_clean()
    budget.save()
    append_event(
        household=period.household,
        actor=actor,
        action=action,
        entity_type="variable_budget",
        entity_id=budget.pk,
        request_id=request_id,
        before=before,
        after={
            "pay_period_id": period.pk,
            "category_id": locked_category.pk,
            "planned_amount": budget.planned_amount,
            "notes": budget.notes,
        },
    )
    return budget


@transaction.atomic
def delete_variable_budget(
    *,
    variable_budget: VariableBudget,
    actor: User,
    request_id: str,
    reason: str,
) -> None:
    budget = (
        VariableBudget.objects.select_for_update()
        .select_related("pay_period", "pay_period__household", "category")
        .get(pk=variable_budget.pk)
    )
    require_household_membership(actor, budget.pay_period.household)
    if budget.pay_period.status == PayPeriod.Status.CLOSED:
        raise ValidationError("Reopen the closed paycheck period before changing its budget.")
    if not reason.strip():
        raise ValidationError("Removing a category budget requires a reason.")
    payload = {
        "pay_period_id": budget.pay_period_id,
        "category_id": budget.category_id,
        "planned_amount": budget.planned_amount,
    }
    budget_id = budget.pk
    household = budget.pay_period.household
    budget.delete()
    append_event(
        household=household,
        actor=actor,
        action="budget.variable_deleted",
        entity_type="variable_budget",
        entity_id=budget_id,
        request_id=request_id,
        before=payload,
        reason=reason.strip(),
    )
