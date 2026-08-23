from __future__ import annotations

import uuid
from decimal import Decimal
from typing import Any, TypeVar

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import models
from django.db.models.functions import Lower

from households.models import Category, Household

_ModelT = TypeVar("_ModelT", bound=models.Model)


class ServiceOnlyQuerySet(models.QuerySet[_ModelT]):
    """Prevent ordinary ORM paths from changing committed financial history."""

    def create(self, **kwargs: Any) -> _ModelT:
        raise ValidationError("Committed ledger records must use a ledger service.")

    def delete(self) -> tuple[int, dict[str, int]]:
        raise ValidationError("Committed ledger records cannot be deleted.")

    def update(self, **kwargs: Any) -> int:
        raise ValidationError("Committed ledger records cannot be updated.")

    def bulk_create(self, *args: Any, **kwargs: Any) -> list[_ModelT]:
        raise ValidationError("Committed ledger records must use a ledger service.")

    def bulk_update(self, *args: Any, **kwargs: Any) -> int:
        raise ValidationError("Committed ledger records cannot be updated.")


class ServiceOnlyManager(models.Manager[_ModelT]):
    def get_queryset(self) -> ServiceOnlyQuerySet[_ModelT]:
        return ServiceOnlyQuerySet(self.model, using=self._db)

    def create(self, **kwargs: Any) -> _ModelT:
        raise ValidationError("Committed ledger records must use a ledger service.")


class ServiceCreatedModel(models.Model):
    """Append-only base for records created by a transactional domain service."""

    class Meta:
        abstract = True

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not getattr(self, "_service_authorized", False):
            raise ValidationError("Committed ledger records must use a ledger service.")
        if not self._state.adding:
            raise ValidationError("Committed ledger records cannot be updated.")
        super().save(*args, force_insert=True, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError("Committed ledger records cannot be deleted.")


class FinancialAccount(models.Model):
    class AccountType(models.TextChoices):
        CHECKING = "checking", "Checking"
        SAVINGS = "savings", "Savings"
        CASH = "cash", "Cash"
        CREDIT_CARD = "credit_card", "Credit card"
        OTHER = "other", "Other"

    class Classification(models.TextChoices):
        ASSET = "asset", "Asset"
        LIABILITY = "liability", "Liability"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    household = models.ForeignKey(
        Household,
        on_delete=models.CASCADE,
        related_name="financial_accounts",
    )
    name = models.CharField(max_length=120)
    account_type = models.CharField(max_length=20, choices=AccountType.choices)
    classification = models.CharField(max_length=12, choices=Classification.choices)
    last_four = models.CharField(
        max_length=4,
        blank=True,
        validators=[RegexValidator(r"^[0-9]{4}$", "Enter exactly four digits.")],
    )
    notes = models.CharField(max_length=500, blank=True)
    archived_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_financial_accounts",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("archived_at", "name")
        constraints = [
            models.UniqueConstraint(
                models.F("household"),
                Lower("name"),
                name="ledger_account_hh_name_ci_unique",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(
                        account_type__in=(
                            "checking",
                            "savings",
                            "cash",
                        ),
                        classification="asset",
                    )
                    | models.Q(
                        account_type="credit_card",
                        classification="liability",
                    )
                    | models.Q(account_type="other")
                ),
                name="ledger_account_type_class_valid",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.household}: {self.name}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        self.name = self.name.strip()
        self.last_four = self.last_four.strip()
        self.notes = self.notes.strip()
        super().save(*args, **kwargs)

    @property
    def is_archived(self) -> bool:
        return self.archived_at is not None

    def clean(self) -> None:
        self.name = self.name.strip()
        self.last_four = self.last_four.strip()
        self.notes = self.notes.strip()
        if not self.name:
            raise ValidationError({"name": "Financial account name is required."})


class JournalEntry(ServiceCreatedModel):
    class EntryType(models.TextChoices):
        INCOME = "income", "Income"
        EXPENSE = "expense", "Expense or purchase"
        TRANSFER = "transfer", "Account transfer"
        DEBT_PAYMENT = "debt_payment", "Debt payment"
        GOAL_CONTRIBUTION = "goal_contribution", "Goal contribution"
        INTEREST_FEE = "interest_fee", "Interest or fee"
        BALANCE_ADJUSTMENT = "balance_adjustment", "Balance adjustment"

    class Provenance(models.TextChoices):
        MANUAL = "manual", "Manual"
        IMPORTED = "imported", "Imported"
        SYSTEM = "system", "System"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    household = models.ForeignKey(
        Household,
        on_delete=models.PROTECT,
        related_name="journal_entries",
    )
    effective_at = models.DateTimeField()
    entry_type = models.CharField(max_length=24, choices=EntryType.choices)
    description = models.CharField(max_length=200)
    category = models.ForeignKey(
        Category,
        on_delete=models.PROTECT,
        related_name="journal_entries",
        null=True,
        blank=True,
    )
    provenance = models.CharField(
        max_length=12,
        choices=Provenance.choices,
        default=Provenance.MANUAL,
    )
    note = models.CharField(max_length=500, blank=True)
    receipt_reference = models.CharField(max_length=255, blank=True)
    idempotency_key = models.CharField(max_length=64, blank=True)
    reversal_of = models.OneToOneField(
        "self",
        on_delete=models.PROTECT,
        related_name="reversal_entry",
        null=True,
        blank=True,
    )
    replacement_for = models.ForeignKey(
        "self",
        on_delete=models.PROTECT,
        related_name="replacement_entries",
        null=True,
        blank=True,
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_journal_entries",
    )
    committed_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    objects = ServiceOnlyManager["JournalEntry"]()

    class Meta:
        ordering = ("-effective_at", "-created_at")
        constraints = [
            models.CheckConstraint(
                condition=~models.Q(description=""),
                name="ledger_entry_description_not_empty",
            ),
            models.CheckConstraint(
                condition=(models.Q(category__isnull=False) | ~models.Q(entry_type="expense")),
                name="ledger_expense_category_required",
            ),
            models.CheckConstraint(
                condition=(models.Q(category__isnull=True) | models.Q(entry_type="expense")),
                name="ledger_category_only_for_expense",
            ),
            models.CheckConstraint(
                condition=~models.Q(id=models.F("reversal_of")),
                name="ledger_entry_not_self_reversal",
            ),
            models.UniqueConstraint(
                fields=("household", "idempotency_key"),
                condition=~models.Q(idempotency_key=""),
                name="ledger_entry_hh_idempotency_unique",
            ),
        ]
        indexes = [
            models.Index(fields=("household", "effective_at"), name="ledger_entry_hh_effective"),
            models.Index(fields=("household", "entry_type"), name="ledger_entry_hh_type"),
        ]

    def __str__(self) -> str:
        return f"{self.effective_at.date()}: {self.description}"


class JournalPosting(ServiceCreatedModel):
    class Side(models.TextChoices):
        DEBIT = "debit", "Debit"
        CREDIT = "credit", "Credit"

    class InternalAccount(models.TextChoices):
        INCOME = "income", "Income"
        EXPENSE = "expense", "Expense"
        ADJUSTMENT = "adjustment", "Balance adjustment"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    entry = models.ForeignKey(
        JournalEntry,
        on_delete=models.PROTECT,
        related_name="postings",
    )
    side = models.CharField(max_length=6, choices=Side.choices)
    amount = models.DecimalField(max_digits=18, decimal_places=2)
    financial_account = models.ForeignKey(
        FinancialAccount,
        on_delete=models.PROTECT,
        related_name="postings",
        null=True,
        blank=True,
    )
    internal_account = models.CharField(
        max_length=16,
        choices=InternalAccount.choices,
        blank=True,
    )
    currency = models.CharField(
        max_length=3,
        validators=[RegexValidator(r"^[A-Z]{3}$", "Use a three-letter currency code.")],
    )

    objects = ServiceOnlyManager["JournalPosting"]()

    class Meta:
        ordering = ("entry_id", "id")
        constraints = [
            models.CheckConstraint(
                condition=models.Q(amount__gt=Decimal("0")),
                name="ledger_posting_amount_positive",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(financial_account__isnull=False, internal_account="")
                    | (models.Q(financial_account__isnull=True) & ~models.Q(internal_account=""))
                ),
                name="ledger_posting_exactly_one_account",
            ),
        ]
        indexes = [
            models.Index(fields=("financial_account", "entry"), name="ledger_posting_account_entry")
        ]

    def __str__(self) -> str:
        target = self.financial_account_id or self.internal_account
        return f"{self.entry_id}: {self.side} {self.amount} {target}"


class BalanceSnapshot(ServiceCreatedModel):
    class Source(models.TextChoices):
        MANUAL = "manual", "Manual"
        INTEGRATION = "integration", "Future integration"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    household = models.ForeignKey(
        Household,
        on_delete=models.PROTECT,
        related_name="balance_snapshots",
    )
    financial_account = models.ForeignKey(
        FinancialAccount,
        on_delete=models.PROTECT,
        related_name="balance_snapshots",
    )
    observed_balance = models.DecimalField(max_digits=18, decimal_places=2)
    observed_at = models.DateTimeField()
    source = models.CharField(max_length=16, choices=Source.choices, default=Source.MANUAL)
    note = models.CharField(max_length=500, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_balance_snapshots",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    objects = ServiceOnlyManager["BalanceSnapshot"]()

    class Meta:
        ordering = ("-observed_at", "-created_at")
        indexes = [
            models.Index(
                fields=("financial_account", "observed_at"),
                name="ledger_snapshot_account_time",
            )
        ]

    def __str__(self) -> str:
        return f"{self.financial_account_id}: {self.observed_balance} at {self.observed_at}"
