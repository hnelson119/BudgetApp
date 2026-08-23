from __future__ import annotations

import uuid
from collections.abc import Collection, Iterable
from datetime import date, timedelta
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from households.models import Household


class PayPeriod(models.Model):
    class Status(models.TextChoices):
        PROJECTED = "projected", "Projected"
        OPEN = "open", "Open"
        CLOSING_REVIEW = "closing_review", "Closing review"
        CLOSED = "closed", "Closed"
        REOPENED = "reopened", "Reopened"

    class BoundarySource(models.TextChoices):
        EXPECTED = "expected", "Expected anchor schedule"
        ACTUAL = "actual", "Confirmed actual paycheck"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    household = models.ForeignKey(
        Household,
        on_delete=models.PROTECT,
        related_name="pay_periods",
    )
    start_date = models.DateField()
    next_start_date = models.DateField()
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PROJECTED)
    boundary_source = models.CharField(
        max_length=12,
        choices=BoundarySource.choices,
        default=BoundarySource.EXPECTED,
    )
    boundary_revision = models.PositiveIntegerField(default=1)
    closed_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_pay_periods",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("start_date",)
        constraints = [
            models.UniqueConstraint(
                fields=("household", "start_date"),
                name="periods_period_hh_start_unique",
            ),
            models.CheckConstraint(
                condition=models.Q(next_start_date__gt=models.F("start_date")),
                name="periods_period_positive_range",
            ),
        ]
        indexes = [models.Index(fields=("household", "status"), name="periods_period_hh_status")]

    def __str__(self) -> str:
        return f"{self.household}: {self.start_date} to {self.display_end_date}"

    @property
    def display_end_date(self) -> date:
        return self.next_start_date - timedelta(days=1)

    def contains(self, value: date) -> bool:
        return self.start_date <= value < self.next_start_date

    def clean(self) -> None:
        if self.next_start_date <= self.start_date:
            raise ValidationError({"next_start_date": "A pay period must have a positive range."})
        overlaps = PayPeriod.objects.filter(
            household=self.household,
            start_date__lt=self.next_start_date,
            next_start_date__gt=self.start_date,
        )
        if self.pk:
            overlaps = overlaps.exclude(pk=self.pk)
        if overlaps.exists():
            raise ValidationError("Pay periods for one household cannot overlap.")


class ClosingRevisionQuerySet(models.QuerySet["PayPeriodClosingRevision"]):
    def create(self, **kwargs: Any) -> PayPeriodClosingRevision:
        raise ValidationError("Closing revisions must use a period lifecycle service.")

    def delete(self) -> tuple[int, dict[str, int]]:
        raise ValidationError("Closing revisions cannot be deleted.")

    def update(self, **kwargs: Any) -> int:
        raise ValidationError("Closing revisions cannot be updated.")

    def bulk_create(
        self,
        objs: Iterable[PayPeriodClosingRevision],
        batch_size: int | None = None,
        ignore_conflicts: bool = False,
        update_conflicts: bool = False,
        update_fields: Collection[str] | None = None,
        unique_fields: Collection[str] | None = None,
    ) -> list[PayPeriodClosingRevision]:
        raise ValidationError("Closing revisions must use a period lifecycle service.")

    def bulk_update(
        self,
        objs: Iterable[PayPeriodClosingRevision],
        fields: Iterable[str],
        batch_size: int | None = None,
    ) -> int:
        raise ValidationError("Closing revisions cannot be updated.")


class ClosingRevisionManager(models.Manager["PayPeriodClosingRevision"]):
    def get_queryset(self) -> ClosingRevisionQuerySet:
        return ClosingRevisionQuerySet(self.model, using=self._db)

    def create(self, **kwargs: Any) -> PayPeriodClosingRevision:
        raise ValidationError("Closing revisions must use a period lifecycle service.")


class PayPeriodClosingRevision(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    pay_period = models.ForeignKey(
        PayPeriod,
        on_delete=models.PROTECT,
        related_name="closing_revisions",
    )
    revision_number = models.PositiveIntegerField()
    closing_surplus = models.DecimalField(max_digits=18, decimal_places=2)
    reserve_delta = models.DecimalField(max_digits=18, decimal_places=2)
    reason = models.CharField(max_length=500, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_period_closing_revisions",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    objects = ClosingRevisionManager()

    class Meta:
        ordering = ("pay_period_id", "revision_number")
        constraints = [
            models.UniqueConstraint(
                fields=("pay_period", "revision_number"),
                name="periods_closing_period_revision_unique",
            )
        ]

    def __str__(self) -> str:
        return f"{self.pay_period_id} closing revision {self.revision_number}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not getattr(self, "_service_authorized", False):
            raise ValidationError("Closing revisions must use a period lifecycle service.")
        if not self._state.adding:
            raise ValidationError("Closing revisions cannot be updated.")
        super().save(*args, force_insert=True, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError("Closing revisions cannot be deleted.")
