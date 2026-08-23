from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import QuerySet, Sum
from django.utils import timezone

from audit.services import append_event
from households.models import Category, Household
from households.services.access import require_household_membership
from identity.models import User
from ledger.models import BalanceSnapshot, FinancialAccount, JournalEntry, JournalPosting


@dataclass(frozen=True)
class AccountReconciliation:
    calculated_balance: Decimal
    observed_balance: Decimal | None
    variance: Decimal | None
    snapshot: BalanceSnapshot | None


def calculated_account_balance(
    account: FinancialAccount,
    *,
    as_of: datetime | None = None,
) -> Decimal:
    postings = JournalPosting.objects.filter(financial_account=account)
    if as_of is not None:
        if timezone.is_naive(as_of):
            raise ValidationError("Balance calculation timestamps must include a timezone.")
        postings = postings.filter(entry__effective_at__lte=as_of)
    totals = {
        row["side"]: row["total"] for row in postings.values("side").annotate(total=Sum("amount"))
    }
    debits = totals.get(JournalPosting.Side.DEBIT, Decimal("0.00"))
    credits = totals.get(JournalPosting.Side.CREDIT, Decimal("0.00"))
    if account.classification == FinancialAccount.Classification.ASSET:
        return debits - credits
    return credits - debits


def account_reconciliation(account: FinancialAccount) -> AccountReconciliation:
    snapshot = BalanceSnapshot.objects.filter(financial_account=account).first()
    if snapshot is None:
        calculated = calculated_account_balance(account)
        return AccountReconciliation(calculated, None, None, None)
    calculated = calculated_account_balance(account, as_of=snapshot.observed_at)
    return AccountReconciliation(
        calculated,
        snapshot.observed_balance,
        snapshot.observed_balance - calculated,
        snapshot,
    )


def _expense_postings(household: Household) -> QuerySet[JournalPosting]:
    return JournalPosting.objects.filter(
        entry__household=household,
        internal_account=JournalPosting.InternalAccount.EXPENSE,
    )


def _net_expense(postings: QuerySet[JournalPosting]) -> Decimal:
    totals = {
        row["side"]: row["total"] for row in postings.values("side").annotate(total=Sum("amount"))
    }
    debits = totals.get(JournalPosting.Side.DEBIT, Decimal("0.00"))
    credits = totals.get(JournalPosting.Side.CREDIT, Decimal("0.00"))
    return debits - credits


def expense_total(household: Household) -> Decimal:
    """Return net expenses, including interest/fees and entry reversals."""

    return _net_expense(_expense_postings(household))


def categorized_spending_total(
    household: Household,
    *,
    category: Category | None = None,
) -> Decimal:
    """Return purchase spending without counting transfers or debt payments."""

    postings = _expense_postings(household).filter(
        entry__entry_type=JournalEntry.EntryType.EXPENSE,
    )
    if category is not None:
        if category.household_id != household.pk:
            raise ValidationError("The category belongs to another household.")
        postings = postings.filter(entry__category=category)
    return _net_expense(postings)


@transaction.atomic
def record_balance_snapshot(
    *,
    household: Household,
    actor: User,
    account: FinancialAccount,
    observed_balance: Decimal,
    observed_at: datetime,
    request_id: str,
    note: str = "",
) -> BalanceSnapshot:
    require_household_membership(actor, household)
    account = FinancialAccount.objects.select_for_update().get(pk=account.pk)
    if account.household_id != household.pk:
        raise ValidationError("The financial account belongs to another household.")
    if account.is_archived:
        raise ValidationError("Archived financial accounts cannot receive balance snapshots.")
    if timezone.is_naive(observed_at):
        raise ValidationError("Balance snapshot timestamps must include a timezone.")
    if not isinstance(observed_balance, Decimal):
        raise ValidationError("Observed balances must use Decimal values.")
    if not observed_balance.is_finite():
        raise ValidationError("Observed balance is invalid.")
    try:
        normalized = observed_balance.quantize(Decimal("0.01"))
    except InvalidOperation as error:
        raise ValidationError("Observed balance is invalid.") from error
    if observed_balance != normalized:
        raise ValidationError("Observed balances may use at most two decimal places.")
    snapshot = BalanceSnapshot(
        household=household,
        financial_account=account,
        observed_balance=normalized,
        observed_at=observed_at,
        note=note.strip(),
        created_by=actor,
    )
    snapshot.full_clean()
    snapshot._service_authorized = True  # type: ignore[attr-defined]
    snapshot.save()
    calculated = calculated_account_balance(account, as_of=snapshot.observed_at)
    variance = snapshot.observed_balance - calculated
    append_event(
        household=household,
        actor=actor,
        action="account.balance_observed",
        entity_type="balance_snapshot",
        entity_id=snapshot.pk,
        request_id=request_id,
        after={
            "account_id": account.pk,
            "observed_balance": snapshot.observed_balance,
            "calculated_balance": calculated,
            "variance": variance,
        },
    )
    return snapshot
