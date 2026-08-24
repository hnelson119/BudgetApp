from __future__ import annotations

import uuid
from collections.abc import Collection, Iterable
from decimal import Decimal
from typing import Any, TypeVar

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from debts.models import DebtAccount
from households.models import Household
from ledger.models import FinancialAccount, JournalEntry
from periods.models import PayPeriod
from reserves.models import ReserveEntry
from schedules.models import Occurrence, RecurringSource

_ModelT = TypeVar("_ModelT", bound=models.Model)


class GoalServiceQuerySet(models.QuerySet[_ModelT]):
    """Keep goal history behind audited services."""

    def create(self, **kwargs: Any) -> _ModelT:
        raise ValidationError("Goal records must use a goal service.")

    def delete(self) -> tuple[int, dict[str, int]]:
        raise ValidationError("Goal records cannot be deleted.")

    def update(self, **kwargs: Any) -> int:
        raise ValidationError("Goal records cannot be updated.")

    def bulk_create(
        self,
        objs: Iterable[_ModelT],
        batch_size: int | None = None,
        ignore_conflicts: bool = False,
        update_conflicts: bool = False,
        update_fields: Collection[str] | None = None,
        unique_fields: Collection[str] | None = None,
    ) -> list[_ModelT]:
        raise ValidationError("Goal records must use a goal service.")

    def bulk_update(
        self,
        objs: Iterable[_ModelT],
        fields: Iterable[str],
        batch_size: int | None = None,
    ) -> int:
        raise ValidationError("Goal records cannot be updated.")


class GoalServiceManager(models.Manager[_ModelT]):
    def get_queryset(self) -> GoalServiceQuerySet[_ModelT]:
        return GoalServiceQuerySet(self.model, using=self._db)

    def create(self, **kwargs: Any) -> _ModelT:
        raise ValidationError("Goal records must use a goal service.")


class ImmutableGoalRecord(models.Model):
    class Meta:
        abstract = True

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding:
            raise ValidationError("Historical goal records cannot be updated.")
        if not getattr(self, "_service_authorized", False):
            raise ValidationError("Goal records must use a goal service.")
        try:
            super().save(*args, force_insert=True, **kwargs)
        finally:
            del self._service_authorized  # type: ignore[attr-defined]

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError("Goal records cannot be deleted.")


class Goal(ImmutableGoalRecord):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    household = models.ForeignKey(
        Household,
        on_delete=models.PROTECT,
        related_name="goals",
    )
    opening_amount = models.DecimalField(max_digits=18, decimal_places=2, default=Decimal("0.00"))
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_goals",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    objects = GoalServiceManager["Goal"]()

    class Meta:
        ordering = ("created_at", "id")
        constraints = [
            models.CheckConstraint(
                condition=models.Q(opening_amount__gte=Decimal("0.00")),
                name="goals_opening_amount_nonnegative",
            )
        ]

    def __str__(self) -> str:
        latest = self.revisions.order_by("-revision_number").first()
        return latest.name if latest else str(self.pk)


class GoalRevision(ImmutableGoalRecord):
    class GoalType(models.TextChoices):
        SAVINGS = "savings", "Savings"
        DEBT_PAYOFF = "debt_payoff", "Debt payoff"
        INVESTING = "investing", "Investing"

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        PAUSED = "paused", "Paused"
        COMPLETED = "completed", "Completed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    goal = models.ForeignKey(Goal, on_delete=models.PROTECT, related_name="revisions")
    revision_number = models.PositiveIntegerField()
    effective_from = models.DateField()
    name = models.CharField(max_length=120)
    goal_type = models.CharField(max_length=16, choices=GoalType.choices)
    target_amount = models.DecimalField(max_digits=18, decimal_places=2)
    target_date = models.DateField(null=True, blank=True)
    contribution_per_period = models.DecimalField(
        max_digits=18,
        decimal_places=2,
        default=Decimal("0.00"),
    )
    priority = models.PositiveSmallIntegerField(default=1)
    status = models.CharField(max_length=12, choices=Status.choices, default=Status.ACTIVE)
    automatic_excess_allocation = models.BooleanField(default=False)
    source_account = models.ForeignKey(
        FinancialAccount,
        on_delete=models.PROTECT,
        related_name="goal_source_revisions",
    )
    destination_account = models.ForeignKey(
        FinancialAccount,
        on_delete=models.PROTECT,
        related_name="goal_destination_revisions",
        null=True,
        blank=True,
    )
    linked_debt = models.ForeignKey(
        DebtAccount,
        on_delete=models.PROTECT,
        related_name="goal_revisions",
        null=True,
        blank=True,
    )
    notes = models.CharField(max_length=500, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_goal_revisions",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    objects = GoalServiceManager["GoalRevision"]()

    class Meta:
        ordering = ("goal_id", "revision_number")
        constraints = [
            models.UniqueConstraint(
                fields=("goal", "revision_number"),
                name="goals_revision_goal_number_unique",
            ),
            models.UniqueConstraint(
                fields=("goal", "effective_from"),
                name="goals_revision_goal_effective_unique",
            ),
            models.CheckConstraint(
                condition=models.Q(target_amount__gt=Decimal("0.00")),
                name="goals_revision_target_positive",
            ),
            models.CheckConstraint(
                condition=models.Q(contribution_per_period__gte=Decimal("0.00")),
                name="goals_revision_contribution_nonnegative",
            ),
            models.CheckConstraint(
                condition=models.Q(priority__gt=0),
                name="goals_revision_priority_positive",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(target_date__isnull=True)
                    | models.Q(target_date__gte=models.F("effective_from"))
                ),
                name="goals_revision_target_date_valid",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(
                        goal_type="debt_payoff",
                        linked_debt__isnull=False,
                        destination_account__isnull=True,
                    )
                    | models.Q(
                        goal_type__in=("savings", "investing"),
                        linked_debt__isnull=True,
                        destination_account__isnull=False,
                    )
                ),
                name="goals_revision_destination_valid",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.name} revision {self.revision_number}"

    def clean(self) -> None:
        self.name = self.name.strip()
        self.notes = self.notes.strip()
        if not self.name:
            raise ValidationError({"name": "Goal name is required."})
        if self.source_account_id:
            if self.source_account.household_id != self.goal.household_id:
                raise ValidationError("The source account belongs to another household.")
            if (
                self.source_account.classification != FinancialAccount.Classification.ASSET
                or self.source_account.is_archived
            ):
                raise ValidationError("The goal source must be an active asset account.")
        if self.destination_account_id:
            destination = self.destination_account
            if destination is None:
                raise ValidationError("The destination account is missing.")
            if destination.household_id != self.goal.household_id:
                raise ValidationError("The destination account belongs to another household.")
            if (
                destination.classification != FinancialAccount.Classification.ASSET
                or destination.is_archived
            ):
                raise ValidationError("The goal destination must be an active asset account.")
            if self.destination_account_id == self.source_account_id:
                raise ValidationError("Goal source and destination accounts must differ.")
        if self.linked_debt_id:
            debt = self.linked_debt
            if debt is None:
                raise ValidationError("The linked debt is missing.")
            if debt.household_id != self.goal.household_id:
                raise ValidationError("The linked debt belongs to another household.")
            if not debt.is_active:
                raise ValidationError("The linked debt must be active.")
            account = debt.financial_account
            if (
                account is None
                or account.classification != FinancialAccount.Classification.LIABILITY
            ):
                raise ValidationError("The linked debt needs a liability financial account.")


class GoalFundingPlan(ImmutableGoalRecord):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    goal = models.OneToOneField(Goal, on_delete=models.PROTECT, related_name="funding_plan")
    source = models.OneToOneField(
        RecurringSource,
        on_delete=models.PROTECT,
        related_name="goal_funding_plan",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_goal_funding_plans",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    objects = GoalServiceManager["GoalFundingPlan"]()

    def __str__(self) -> str:
        return f"Funding plan for {self.goal_id}"

    def clean(self) -> None:
        if self.goal_id and self.source_id:
            if self.goal.household_id != self.source.household_id:
                raise ValidationError("The funding source belongs to another household.")
            if self.source.kind != RecurringSource.Kind.GOAL_CONTRIBUTION:
                raise ValidationError("Goal funding requires a goal-contribution source.")


class GoalContribution(ImmutableGoalRecord):
    class ContributionType(models.TextChoices):
        MANUAL = "manual", "Manual"
        SCHEDULED = "scheduled", "Scheduled"
        RESERVE = "reserve", "Reserve allocation"
        AUTOMATIC = "automatic", "Priority reserve allocation"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    goal = models.ForeignKey(Goal, on_delete=models.PROTECT, related_name="contributions")
    pay_period = models.ForeignKey(
        PayPeriod,
        on_delete=models.PROTECT,
        related_name="goal_contributions",
    )
    occurrence = models.OneToOneField(
        Occurrence,
        on_delete=models.PROTECT,
        related_name="goal_contribution",
        null=True,
        blank=True,
    )
    journal_entry = models.OneToOneField(
        JournalEntry,
        on_delete=models.PROTECT,
        related_name="goal_progress_contribution",
    )
    reserve_entry = models.OneToOneField(
        ReserveEntry,
        on_delete=models.PROTECT,
        related_name="goal_contribution",
        null=True,
        blank=True,
    )
    contribution_type = models.CharField(max_length=12, choices=ContributionType.choices)
    amount = models.DecimalField(max_digits=18, decimal_places=2)
    effective_at = models.DateTimeField()
    reason = models.CharField(max_length=500, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_goal_contributions",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    objects = GoalServiceManager["GoalContribution"]()

    class Meta:
        ordering = ("-effective_at", "-created_at")
        constraints = [
            models.CheckConstraint(
                condition=models.Q(amount__gt=Decimal("0.00")),
                name="goals_contribution_amount_positive",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(
                        contribution_type__in=("reserve", "automatic"),
                        reserve_entry__isnull=False,
                    )
                    | models.Q(
                        contribution_type__in=("manual", "scheduled"),
                        reserve_entry__isnull=True,
                    )
                ),
                name="goals_contribution_reserve_valid",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(contribution_type="scheduled", occurrence__isnull=False)
                    | ~models.Q(contribution_type="scheduled")
                ),
                name="goals_scheduled_occurrence_required",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.goal_id}: {self.amount} ({self.contribution_type})"

    def clean(self) -> None:
        self.reason = self.reason.strip()
        household_id = self.goal.household_id
        if self.pay_period_id and self.pay_period.household_id != household_id:
            raise ValidationError("The paycheck period belongs to another household.")
        if self.journal_entry_id and self.journal_entry.household_id != household_id:
            raise ValidationError("The journal entry belongs to another household.")
        if self.reserve_entry_id:
            reserve_entry = self.reserve_entry
            if reserve_entry is None or reserve_entry.household_id != household_id:
                raise ValidationError("The reserve entry belongs to another household.")
        if self.occurrence_id:
            occurrence = self.occurrence
            if occurrence is None:
                raise ValidationError("The scheduled occurrence is missing.")
            plan = GoalFundingPlan.objects.filter(goal=self.goal).first()
            if plan is None or occurrence.source_id != plan.source_id:
                raise ValidationError("The occurrence does not belong to this goal.")
            if occurrence.pay_period_id != self.pay_period_id:
                raise ValidationError("The occurrence belongs to another paycheck period.")
