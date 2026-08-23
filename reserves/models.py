from __future__ import annotations

import uuid
from collections.abc import Collection, Iterable
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from households.models import Household
from periods.models import PayPeriod, PayPeriodClosingRevision


class ReserveEntryQuerySet(models.QuerySet["ReserveEntry"]):
    def create(self, **kwargs: Any) -> ReserveEntry:
        raise ValidationError("Reserve entries must use a reserve service.")

    def delete(self) -> tuple[int, dict[str, int]]:
        raise ValidationError("Reserve entries cannot be deleted.")

    def update(self, **kwargs: Any) -> int:
        raise ValidationError("Reserve entries cannot be updated.")

    def bulk_create(
        self,
        objs: Iterable[ReserveEntry],
        batch_size: int | None = None,
        ignore_conflicts: bool = False,
        update_conflicts: bool = False,
        update_fields: Collection[str] | None = None,
        unique_fields: Collection[str] | None = None,
    ) -> list[ReserveEntry]:
        raise ValidationError("Reserve entries must use a reserve service.")

    def bulk_update(
        self,
        objs: Iterable[ReserveEntry],
        fields: Iterable[str],
        batch_size: int | None = None,
    ) -> int:
        raise ValidationError("Reserve entries cannot be updated.")


class ReserveEntryManager(models.Manager["ReserveEntry"]):
    def get_queryset(self) -> ReserveEntryQuerySet:
        return ReserveEntryQuerySet(self.model, using=self._db)

    def create(self, **kwargs: Any) -> ReserveEntry:
        raise ValidationError("Reserve entries must use a reserve service.")


class ReserveEntry(models.Model):
    class EntryType(models.TextChoices):
        PERIOD_CLOSE = "period_close", "Period close"
        PERIOD_CORRECTION = "period_correction", "Closed-period correction"
        EXPLICIT_ALLOCATION = "explicit_allocation", "Future explicit allocation"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    household = models.ForeignKey(
        Household,
        on_delete=models.PROTECT,
        related_name="reserve_entries",
    )
    source_period = models.ForeignKey(
        PayPeriod,
        on_delete=models.PROTECT,
        related_name="source_reserve_entries",
    )
    posting_period = models.ForeignKey(
        PayPeriod,
        on_delete=models.PROTECT,
        related_name="posted_reserve_entries",
    )
    closing_revision = models.OneToOneField(
        PayPeriodClosingRevision,
        on_delete=models.PROTECT,
        related_name="reserve_entry",
        null=True,
        blank=True,
    )
    entry_type = models.CharField(max_length=24, choices=EntryType.choices)
    amount = models.DecimalField(max_digits=18, decimal_places=2)
    allocation_label = models.CharField(max_length=120, blank=True)
    reason = models.CharField(max_length=500, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_reserve_entries",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    objects = ReserveEntryManager()

    class Meta:
        ordering = ("created_at", "id")
        indexes = [
            models.Index(fields=("household", "created_at"), name="reserves_entry_hh_created")
        ]
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(
                        entry_type__in=("period_close", "period_correction"),
                        closing_revision__isnull=False,
                        allocation_label="",
                    )
                    | models.Q(
                        entry_type="explicit_allocation",
                        closing_revision__isnull=True,
                        amount__lt=0,
                    )
                ),
                name="reserves_entry_type_fields_valid",
            )
        ]

    def __str__(self) -> str:
        return f"{self.household_id}: {self.amount} ({self.entry_type})"

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not getattr(self, "_service_authorized", False):
            raise ValidationError("Reserve entries must use a reserve service.")
        if not self._state.adding:
            raise ValidationError("Reserve entries cannot be updated.")
        self.allocation_label = self.allocation_label.strip()
        self.reason = self.reason.strip()
        super().save(*args, force_insert=True, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError("Reserve entries cannot be deleted.")
