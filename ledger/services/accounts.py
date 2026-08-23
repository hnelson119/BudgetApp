from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from audit.services import append_event
from households.models import Household
from households.services.access import require_household_membership
from identity.models import User
from ledger.models import FinancialAccount


@transaction.atomic
def create_financial_account(
    *,
    household: Household,
    actor: User,
    name: str,
    account_type: str,
    classification: str,
    request_id: str,
    last_four: str = "",
    notes: str = "",
) -> FinancialAccount:
    require_household_membership(actor, household)
    account = FinancialAccount(
        household=household,
        name=name.strip(),
        account_type=account_type,
        classification=classification,
        last_four=last_four.strip(),
        notes=notes.strip(),
        created_by=actor,
    )
    account.full_clean()
    account.save()
    append_event(
        household=household,
        actor=actor,
        action="account.created",
        entity_type="financial_account",
        entity_id=account.pk,
        request_id=request_id,
        after={
            "name": account.name,
            "account_type": account.account_type,
            "classification": account.classification,
        },
    )
    return account


@transaction.atomic
def update_financial_account(
    *,
    account: FinancialAccount,
    actor: User,
    name: str,
    last_four: str,
    notes: str,
    request_id: str,
) -> FinancialAccount:
    locked = (
        FinancialAccount.objects.select_for_update().select_related("household").get(pk=account.pk)
    )
    require_household_membership(actor, locked.household)
    if locked.is_archived:
        raise ValidationError("Archived financial accounts cannot be edited.")
    before = {"name": locked.name}
    locked.name = name.strip()
    locked.last_four = last_four.strip()
    locked.notes = notes.strip()
    locked.full_clean()
    locked.save(update_fields=("name", "last_four", "notes", "updated_at"))
    append_event(
        household=locked.household,
        actor=actor,
        action="account.updated",
        entity_type="financial_account",
        entity_id=locked.pk,
        request_id=request_id,
        before=before,
        after={"name": locked.name},
    )
    return locked


@transaction.atomic
def archive_financial_account(
    *,
    account: FinancialAccount,
    actor: User,
    request_id: str,
    reason: str,
) -> FinancialAccount:
    locked = (
        FinancialAccount.objects.select_for_update().select_related("household").get(pk=account.pk)
    )
    require_household_membership(actor, locked.household)
    if locked.is_archived:
        return locked
    if not reason.strip():
        raise ValidationError("Archiving a financial account requires a reason.")
    locked.archived_at = timezone.now()
    locked.save(update_fields=("archived_at", "updated_at"))
    append_event(
        household=locked.household,
        actor=actor,
        action="account.archived",
        entity_type="financial_account",
        entity_id=locked.pk,
        request_id=request_id,
        before={"archived_at": None},
        after={"archived_at": locked.archived_at},
        reason=reason.strip(),
    )
    return locked
