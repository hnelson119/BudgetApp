from __future__ import annotations

import uuid
from collections.abc import Collection, Iterable
from decimal import Decimal
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from households.models import Category, Household
from ledger.models import JournalEntry
from periods.models import PayPeriod
from schedules.models import Occurrence


class VariableBudget(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    pay_period = models.ForeignKey(
        PayPeriod,
        on_delete=models.PROTECT,
        related_name="variable_budgets",
    )
    category = models.ForeignKey(
        Category,
        on_delete=models.PROTECT,
        related_name="variable_budgets",
    )
    planned_amount = models.DecimalField(max_digits=18, decimal_places=2)
    notes = models.CharField(max_length=500, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_variable_budgets",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("category__sort_order", "category__name")
        constraints = [
            models.UniqueConstraint(
                fields=("pay_period", "category"),
                name="budgets_variable_period_category_unique",
            ),
            models.CheckConstraint(
                condition=models.Q(planned_amount__gte=Decimal("0")),
                name="budgets_variable_amount_nonnegative",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.pay_period_id}: {self.category.name} {self.planned_amount}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        self.notes = self.notes.strip()
        super().save(*args, **kwargs)

    def clean(self) -> None:
        self.notes = self.notes.strip()
        if self.pay_period_id and self.category_id:
            if self.pay_period.household_id != self.category.household_id:
                raise ValidationError("The category and paycheck period must share a household.")


class ReconciliationLinkQuerySet(models.QuerySet["OccurrenceReconciliation"]):
    def create(self, **kwargs: Any) -> OccurrenceReconciliation:
        raise ValidationError("Reconciliation links must use a budget service.")

    def delete(self) -> tuple[int, dict[str, int]]:
        raise ValidationError("Reconciliation links cannot be deleted.")

    def update(self, **kwargs: Any) -> int:
        raise ValidationError("Reconciliation links cannot be updated.")

    def bulk_create(
        self,
        objs: Iterable[OccurrenceReconciliation],
        batch_size: int | None = None,
        ignore_conflicts: bool = False,
        update_conflicts: bool = False,
        update_fields: Collection[str] | None = None,
        unique_fields: Collection[str] | None = None,
    ) -> list[OccurrenceReconciliation]:
        raise ValidationError("Reconciliation links must use a budget service.")

    def bulk_update(
        self,
        objs: Iterable[OccurrenceReconciliation],
        fields: Iterable[str],
        batch_size: int | None = None,
    ) -> int:
        raise ValidationError("Reconciliation links cannot be updated.")


class ReconciliationLinkManager(models.Manager["OccurrenceReconciliation"]):
    def get_queryset(self) -> ReconciliationLinkQuerySet:
        return ReconciliationLinkQuerySet(self.model, using=self._db)

    def create(self, **kwargs: Any) -> OccurrenceReconciliation:
        raise ValidationError("Reconciliation links must use a budget service.")


class OccurrenceReconciliation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    household = models.ForeignKey(
        Household,
        on_delete=models.PROTECT,
        related_name="occurrence_reconciliations",
    )
    occurrence = models.ForeignKey(
        Occurrence,
        on_delete=models.PROTECT,
        related_name="reconciliations",
    )
    journal_entry = models.ForeignKey(
        JournalEntry,
        on_delete=models.PROTECT,
        related_name="occurrence_reconciliations",
    )
    amount = models.DecimalField(max_digits=18, decimal_places=2)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_occurrence_reconciliations",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    objects = ReconciliationLinkManager()

    class Meta:
        ordering = ("created_at", "id")
        constraints = [
            models.UniqueConstraint(
                fields=("occurrence", "journal_entry"),
                name="budgets_reconciliation_occ_entry_unique",
            ),
            models.CheckConstraint(
                condition=models.Q(amount__gt=Decimal("0")),
                name="budgets_reconciliation_amount_positive",
            ),
        ]
        indexes = [
            models.Index(
                fields=("household", "created_at"),
                name="budgets_reconcile_hh_created",
            )
        ]

    def __str__(self) -> str:
        return f"{self.occurrence_id} ← {self.journal_entry_id}: {self.amount}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not getattr(self, "_service_authorized", False):
            raise ValidationError("Reconciliation links must use a budget service.")
        if not self._state.adding:
            raise ValidationError("Reconciliation links cannot be updated.")
        super().save(*args, force_insert=True, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError("Reconciliation links cannot be deleted.")

    def clean(self) -> None:
        if self.household_id and self.occurrence_id:
            if self.occurrence.source.household_id != self.household_id:
                raise ValidationError("The occurrence belongs to another household.")
        if self.household_id and self.journal_entry_id:
            if self.journal_entry.household_id != self.household_id:
                raise ValidationError("The journal entry belongs to another household.")
