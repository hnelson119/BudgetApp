from __future__ import annotations

import uuid
from collections.abc import Collection, Iterable
from decimal import Decimal
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.functions import Lower

from households.models import Category, Household
from periods.models import PayPeriod
from schedules.recurrence import BusinessDayAdjustment, Frequency


class ImmutableRevisionQuerySet(models.QuerySet["SourceRevision"]):
    def create(self, **kwargs: Any) -> SourceRevision:
        raise ValidationError("Schedule revisions must use a schedule service.")

    def delete(self) -> tuple[int, dict[str, int]]:
        raise ValidationError("Schedule revisions cannot be deleted.")

    def update(self, **kwargs: Any) -> int:
        raise ValidationError("Schedule revisions cannot be updated.")

    def bulk_create(
        self,
        objs: Iterable[SourceRevision],
        batch_size: int | None = None,
        ignore_conflicts: bool = False,
        update_conflicts: bool = False,
        update_fields: Collection[str] | None = None,
        unique_fields: Collection[str] | None = None,
    ) -> list[SourceRevision]:
        raise ValidationError("Schedule revisions must use a schedule service.")

    def bulk_update(
        self,
        objs: Iterable[SourceRevision],
        fields: Iterable[str],
        batch_size: int | None = None,
    ) -> int:
        raise ValidationError("Schedule revisions cannot be updated.")


class ImmutableRevisionManager(models.Manager["SourceRevision"]):
    def get_queryset(self) -> ImmutableRevisionQuerySet:
        return ImmutableRevisionQuerySet(self.model, using=self._db)

    def create(self, **kwargs: Any) -> SourceRevision:
        raise ValidationError("Schedule revisions must use a schedule service.")


class RecurringSource(models.Model):
    class Kind(models.TextChoices):
        INCOME = "income", "Income"
        FIXED_EXPENSE = "fixed_expense", "Fixed expense"
        DEBT_PAYMENT = "debt_payment", "Debt payment"
        GOAL_CONTRIBUTION = "goal_contribution", "Goal contribution"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    household = models.ForeignKey(
        Household,
        on_delete=models.PROTECT,
        related_name="recurring_sources",
    )
    kind = models.CharField(max_length=24, choices=Kind.choices)
    name = models.CharField(max_length=120)
    notes = models.CharField(max_length=500, blank=True)
    archived_at = models.DateTimeField(null=True, blank=True)
    archived_from = models.DateField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_recurring_sources",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("archived_at", "kind", "name")
        constraints = [
            models.UniqueConstraint(
                models.F("household"),
                models.F("kind"),
                Lower("name"),
                name="schedules_source_hh_kind_name_ci_unique",
            )
        ]

    def __str__(self) -> str:
        return f"{self.household}: {self.name}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        self.name = self.name.strip()
        self.notes = self.notes.strip()
        super().save(*args, **kwargs)

    @property
    def is_archived(self) -> bool:
        return self.archived_at is not None

    def clean(self) -> None:
        self.name = self.name.strip()
        self.notes = self.notes.strip()
        if not self.name:
            raise ValidationError({"name": "Recurring source name is required."})


class IncomeSourceDetail(models.Model):
    source = models.OneToOneField(
        RecurringSource,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="income_detail",
    )
    starts_budget_period = models.BooleanField(default=True)
    is_variable = models.BooleanField(default=False)

    def __str__(self) -> str:
        return f"Income settings for {self.source_id}"

    def clean(self) -> None:
        if self.source_id and self.source.kind != RecurringSource.Kind.INCOME:
            raise ValidationError("Income details require an income recurring source.")


class ExpenseSourceDetail(models.Model):
    source = models.OneToOneField(
        RecurringSource,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="expense_detail",
    )
    category = models.ForeignKey(
        Category,
        on_delete=models.PROTECT,
        related_name="fixed_expense_sources",
    )
    is_required = models.BooleanField(default=True)

    def __str__(self) -> str:
        return f"Expense settings for {self.source_id}"

    def clean(self) -> None:
        if self.source_id:
            if self.source.kind != RecurringSource.Kind.FIXED_EXPENSE:
                raise ValidationError("Expense details require a fixed-expense recurring source.")
            if self.category_id and self.category.household_id != self.source.household_id:
                raise ValidationError("The expense category must belong to the source household.")


class SourceRevision(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source = models.ForeignKey(
        RecurringSource,
        on_delete=models.PROTECT,
        related_name="revisions",
    )
    revision_number = models.PositiveIntegerField()
    effective_from = models.DateField()
    expected_amount = models.DecimalField(max_digits=18, decimal_places=2)
    frequency = models.CharField(
        max_length=28,
        choices=((value.value, value.value.replace("_", " ").title()) for value in Frequency),
    )
    interval = models.PositiveSmallIntegerField(default=1)
    start_date = models.DateField()
    end_date = models.DateField(null=True, blank=True)
    weekdays = models.JSONField(default=list, blank=True)
    day_of_month = models.PositiveSmallIntegerField(null=True, blank=True)
    weekday = models.PositiveSmallIntegerField(null=True, blank=True)
    ordinal = models.PositiveSmallIntegerField(null=True, blank=True)
    month_of_year = models.PositiveSmallIntegerField(null=True, blank=True)
    adjustment_policy = models.CharField(
        max_length=12,
        choices=((value.value, value.value.title()) for value in BusinessDayAdjustment),
        default=BusinessDayAdjustment.PREVIOUS,
    )
    holiday_dates = models.JSONField(default=list, blank=True)
    configuration = models.JSONField(default=dict, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_source_revisions",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    objects = ImmutableRevisionManager()

    class Meta:
        ordering = ("source_id", "revision_number")
        constraints = [
            models.UniqueConstraint(
                fields=("source", "revision_number"),
                name="schedules_revision_source_number_unique",
            ),
            models.UniqueConstraint(
                fields=("source", "effective_from"),
                name="schedules_revision_source_effective_unique",
            ),
            models.CheckConstraint(
                condition=models.Q(expected_amount__gte=Decimal("0")),
                name="schedules_revision_amount_nonnegative",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(end_date__isnull=True) | models.Q(end_date__gte=models.F("start_date"))
                ),
                name="schedules_revision_date_range_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(start_date__gte=models.F("effective_from")),
                name="schedules_revision_start_after_effective",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.source_id} revision {self.revision_number}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not getattr(self, "_service_authorized", False):
            raise ValidationError("Schedule revisions must use a schedule service.")
        if not self._state.adding:
            raise ValidationError("Schedule revisions cannot be updated.")
        super().save(*args, force_insert=True, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError("Schedule revisions cannot be deleted.")


class Occurrence(models.Model):
    class Status(models.TextChoices):
        SCHEDULED = "scheduled", "Scheduled"
        MOVED = "moved", "Moved"
        OVERRIDDEN = "overridden", "Overridden"
        COMPLETED = "completed", "Completed"
        CORRECTED = "corrected", "Corrected"
        CANCELLED = "cancelled", "Cancelled"
        SUPERSEDED = "superseded", "Superseded by schedule revision"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    source = models.ForeignKey(
        RecurringSource,
        on_delete=models.PROTECT,
        related_name="occurrences",
    )
    source_revision = models.ForeignKey(
        SourceRevision,
        on_delete=models.PROTECT,
        related_name="occurrences",
    )
    nominal_date = models.DateField()
    generated_expected_date = models.DateField()
    expected_date = models.DateField()
    generated_amount = models.DecimalField(max_digits=18, decimal_places=2)
    planned_amount = models.DecimalField(max_digits=18, decimal_places=2)
    pay_period = models.ForeignKey(
        PayPeriod,
        on_delete=models.PROTECT,
        related_name="occurrences",
        null=True,
        blank=True,
    )
    original_pay_period = models.ForeignKey(
        PayPeriod,
        on_delete=models.PROTECT,
        related_name="moved_from_occurrences",
        null=True,
        blank=True,
    )
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.SCHEDULED)
    actual_amount = models.DecimalField(max_digits=18, decimal_places=2, null=True, blank=True)
    actual_date = models.DateField(null=True, blank=True)
    override_reason = models.CharField(max_length=500, blank=True)
    cancellation_reason = models.CharField(max_length=500, blank=True)
    cancelled_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("expected_date", "source__name")
        constraints = [
            models.UniqueConstraint(
                fields=("source_revision", "nominal_date"),
                name="schedules_occurrence_revision_nominal_unique",
            ),
            models.CheckConstraint(
                condition=models.Q(generated_amount__gte=Decimal("0")),
                name="schedules_occurrence_generated_nonnegative",
            ),
            models.CheckConstraint(
                condition=models.Q(planned_amount__gte=Decimal("0")),
                name="schedules_occurrence_planned_nonnegative",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(actual_amount__isnull=True) | models.Q(actual_amount__gte=Decimal("0"))
                ),
                name="schedules_occurrence_actual_nonnegative",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(pay_period__isnull=False)
                    | models.Q(status__in=("cancelled", "superseded"))
                ),
                name="schedules_active_occurrence_has_period",
            ),
        ]
        indexes = [
            models.Index(fields=("source", "expected_date"), name="schedules_occ_source_date"),
            models.Index(fields=("pay_period", "status"), name="schedules_occ_period_status"),
        ]

    def __str__(self) -> str:
        return f"{self.source}: {self.expected_date}"

    @property
    def is_protected_from_regeneration(self) -> bool:
        return self.status != self.Status.SCHEDULED

    def clean(self) -> None:
        if self.source_revision_id and self.source_id:
            if self.source_revision.source_id != self.source_id:
                raise ValidationError("Occurrence source and revision do not match.")
