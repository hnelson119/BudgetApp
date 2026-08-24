from __future__ import annotations

import uuid
from collections.abc import Collection, Iterable
from decimal import Decimal
from typing import Any, TypeVar

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.functions import Lower

from households.models import Household
from ledger.models import FinancialAccount
from schedules.models import RecurringSource

_ModelT = TypeVar("_ModelT", bound=models.Model)


class DebtServiceQuerySet(models.QuerySet[_ModelT]):
    """Prevent ordinary ORM paths from bypassing debt services and audit history."""

    def create(self, **kwargs: Any) -> _ModelT:
        raise ValidationError("Debt records must use a debt service.")

    def delete(self) -> tuple[int, dict[str, int]]:
        raise ValidationError("Debt records cannot be deleted.")

    def update(self, **kwargs: Any) -> int:
        raise ValidationError("Debt records must use a debt service.")

    def bulk_create(
        self,
        objs: Iterable[_ModelT],
        batch_size: int | None = None,
        ignore_conflicts: bool = False,
        update_conflicts: bool = False,
        update_fields: Collection[str] | None = None,
        unique_fields: Collection[str] | None = None,
    ) -> list[_ModelT]:
        raise ValidationError("Debt records must use a debt service.")

    def bulk_update(
        self,
        objs: Iterable[_ModelT],
        fields: Iterable[str],
        batch_size: int | None = None,
    ) -> int:
        raise ValidationError("Debt records must use a debt service.")


class DebtServiceManager(models.Manager[_ModelT]):
    def get_queryset(self) -> DebtServiceQuerySet[_ModelT]:
        return DebtServiceQuerySet(self.model, using=self._db)

    def create(self, **kwargs: Any) -> _ModelT:
        raise ValidationError("Debt records must use a debt service.")


class DebtManagedModel(models.Model):
    class Meta:
        abstract = True

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not getattr(self, "_service_authorized", False):
            raise ValidationError("Debt records must use a debt service.")
        try:
            super().save(*args, **kwargs)
        finally:
            del self._service_authorized  # type: ignore[attr-defined]

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError("Debt records cannot be deleted.")


class ImmutableDebtRecord(DebtManagedModel):
    class Meta:
        abstract = True

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not self._state.adding:
            raise ValidationError("Historical debt records cannot be updated.")
        super().save(*args, force_insert=True, **kwargs)


class DebtAccount(DebtManagedModel):
    class DebtType(models.TextChoices):
        CREDIT_CARD = "credit_card", "Credit card"
        AUTO_LOAN = "auto_loan", "Auto loan"
        STUDENT_LOAN = "student_loan", "Student loan"
        MORTGAGE = "mortgage", "Mortgage"
        PERSONAL_LOAN = "personal_loan", "Personal loan"
        MEDICAL = "medical", "Medical debt"
        OTHER = "other", "Other debt"

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        PAID_OFF = "paid_off", "Paid off"
        ARCHIVED = "archived", "Archived"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    household = models.ForeignKey(
        Household,
        on_delete=models.PROTECT,
        related_name="debt_accounts",
    )
    financial_account = models.OneToOneField(
        FinancialAccount,
        on_delete=models.PROTECT,
        related_name="debt_account",
        null=True,
        blank=True,
    )
    name = models.CharField(max_length=120)
    debt_type = models.CharField(max_length=20, choices=DebtType.choices)
    current_balance = models.DecimalField(max_digits=18, decimal_places=2)
    status = models.CharField(max_length=12, choices=Status.choices, default=Status.ACTIVE)
    status_changed_at = models.DateTimeField(null=True, blank=True)
    last_reconciled_on = models.DateField(null=True, blank=True)
    notes = models.CharField(max_length=500, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_debt_accounts",
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="updated_debt_accounts",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = DebtServiceManager["DebtAccount"]()

    class Meta:
        ordering = ("status", "name")
        constraints = [
            models.UniqueConstraint(
                models.F("household"),
                Lower("name"),
                name="debts_account_hh_name_ci_unique",
            ),
            models.CheckConstraint(
                condition=models.Q(current_balance__gte=Decimal("0")),
                name="debts_account_balance_nonnegative",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(status="active", status_changed_at__isnull=True)
                    | (~models.Q(status="active") & models.Q(status_changed_at__isnull=False))
                ),
                name="debts_account_status_timestamp_valid",
            ),
            models.CheckConstraint(
                condition=(~models.Q(status="paid_off") | models.Q(current_balance=Decimal("0"))),
                name="debts_paid_off_balance_zero",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.household}: {self.name}"

    @property
    def is_active(self) -> bool:
        return self.status == self.Status.ACTIVE

    def clean(self) -> None:
        self.name = self.name.strip()
        self.notes = self.notes.strip()
        if not self.name:
            raise ValidationError({"name": "Debt name is required."})
        linked_account = self.financial_account
        if linked_account is not None:
            if linked_account.household_id != self.household_id:
                raise ValidationError("The linked financial account belongs to another household.")
            if linked_account.classification != FinancialAccount.Classification.LIABILITY:
                raise ValidationError("A debt must link to a liability account.")
            if (
                self.debt_type == self.DebtType.CREDIT_CARD
                and linked_account.account_type != FinancialAccount.AccountType.CREDIT_CARD
            ):
                raise ValidationError("A credit-card debt must link to a credit-card account.")


class DebtTermsRevision(ImmutableDebtRecord):
    class InterestMethod(models.TextChoices):
        MONTHLY = "monthly", "Monthly APR / 12"
        DAILY = "daily", "Daily simple interest"

    class DayCountBasis(models.TextChoices):
        ACTUAL_365 = "actual_365", "Actual / 365"
        ACTUAL_360 = "actual_360", "Actual / 360"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    debt = models.ForeignKey(
        DebtAccount,
        on_delete=models.PROTECT,
        related_name="terms_revisions",
    )
    revision_number = models.PositiveIntegerField()
    effective_from = models.DateField()
    annual_percentage_rate = models.DecimalField(max_digits=7, decimal_places=4)
    interest_method = models.CharField(
        max_length=12,
        choices=InterestMethod.choices,
        default=InterestMethod.MONTHLY,
    )
    day_count_basis = models.CharField(
        max_length=12,
        choices=DayCountBasis.choices,
        default=DayCountBasis.ACTUAL_365,
    )
    minimum_payment = models.DecimalField(max_digits=18, decimal_places=2)
    recurring_extra_payment = models.DecimalField(
        max_digits=18,
        decimal_places=2,
        default=Decimal("0.00"),
    )
    due_day = models.PositiveSmallIntegerField()
    custom_priority = models.PositiveSmallIntegerField(default=100)
    projection_notes = models.CharField(max_length=500, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_debt_terms_revisions",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    objects = DebtServiceManager["DebtTermsRevision"]()

    class Meta:
        ordering = ("debt_id", "revision_number")
        constraints = [
            models.UniqueConstraint(
                fields=("debt", "revision_number"),
                name="debts_terms_debt_revision_unique",
            ),
            models.UniqueConstraint(
                fields=("debt", "effective_from"),
                name="debts_terms_debt_effective_unique",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(annual_percentage_rate__gte=Decimal("0"))
                    & models.Q(annual_percentage_rate__lt=Decimal("1000"))
                ),
                name="debts_terms_apr_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(minimum_payment__gte=Decimal("0")),
                name="debts_terms_minimum_nonnegative",
            ),
            models.CheckConstraint(
                condition=models.Q(recurring_extra_payment__gte=Decimal("0")),
                name="debts_terms_extra_nonnegative",
            ),
            models.CheckConstraint(
                condition=models.Q(due_day__gte=1) & models.Q(due_day__lte=31),
                name="debts_terms_due_day_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(custom_priority__gte=1),
                name="debts_terms_priority_positive",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.debt_id} terms revision {self.revision_number}"

    def clean(self) -> None:
        self.projection_notes = self.projection_notes.strip()


class DebtStatement(ImmutableDebtRecord):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    debt = models.ForeignKey(
        DebtAccount,
        on_delete=models.PROTECT,
        related_name="statements",
    )
    supersedes = models.OneToOneField(
        "self",
        on_delete=models.PROTECT,
        related_name="superseded_by",
        null=True,
        blank=True,
    )
    statement_date = models.DateField()
    period_start = models.DateField(null=True, blank=True)
    period_end = models.DateField(null=True, blank=True)
    due_date = models.DateField(null=True, blank=True)
    statement_balance = models.DecimalField(max_digits=18, decimal_places=2)
    annual_percentage_rate = models.DecimalField(max_digits=7, decimal_places=4)
    minimum_payment = models.DecimalField(max_digits=18, decimal_places=2)
    principal_paid = models.DecimalField(max_digits=18, decimal_places=2, default=Decimal("0.00"))
    interest_charged = models.DecimalField(
        max_digits=18,
        decimal_places=2,
        default=Decimal("0.00"),
    )
    fees_charged = models.DecimalField(max_digits=18, decimal_places=2, default=Decimal("0.00"))
    escrow_paid = models.DecimalField(max_digits=18, decimal_places=2, default=Decimal("0.00"))
    pmi_paid = models.DecimalField(max_digits=18, decimal_places=2, default=Decimal("0.00"))
    extra_principal_paid = models.DecimalField(
        max_digits=18,
        decimal_places=2,
        default=Decimal("0.00"),
    )
    notes = models.CharField(max_length=500, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_debt_statements",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    objects = DebtServiceManager["DebtStatement"]()

    class Meta:
        ordering = ("-statement_date", "-created_at")
        constraints = [
            models.CheckConstraint(
                condition=models.Q(statement_balance__gte=Decimal("0")),
                name="debts_statement_balance_nonnegative",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(annual_percentage_rate__gte=Decimal("0"))
                    & models.Q(annual_percentage_rate__lt=Decimal("1000"))
                ),
                name="debts_statement_apr_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(minimum_payment__gte=Decimal("0")),
                name="debts_statement_minimum_nonnegative",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(principal_paid__gte=Decimal("0"))
                    & models.Q(interest_charged__gte=Decimal("0"))
                    & models.Q(fees_charged__gte=Decimal("0"))
                    & models.Q(escrow_paid__gte=Decimal("0"))
                    & models.Q(pmi_paid__gte=Decimal("0"))
                    & models.Q(extra_principal_paid__gte=Decimal("0"))
                ),
                name="debts_statement_components_nonnegative",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(period_start__isnull=True, period_end__isnull=True)
                    | (
                        models.Q(period_start__isnull=False, period_end__isnull=False)
                        & models.Q(period_end__gte=models.F("period_start"))
                    )
                ),
                name="debts_statement_period_valid",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(due_date__isnull=True)
                    | models.Q(due_date__gte=models.F("statement_date"))
                ),
                name="debts_statement_due_date_valid",
            ),
            models.CheckConstraint(
                condition=~models.Q(id=models.F("supersedes")),
                name="debts_statement_not_self_superseding",
            ),
        ]
        indexes = [
            models.Index(
                fields=("debt", "statement_date"),
                name="debts_statement_debt_date",
            )
        ]

    def __str__(self) -> str:
        return f"{self.debt_id}: {self.statement_date} {self.statement_balance}"

    def clean(self) -> None:
        self.notes = self.notes.strip()
        superseded = self.supersedes
        if superseded is not None:
            if superseded.debt_id != self.debt_id:
                raise ValidationError("A correction must supersede a statement for the same debt.")
            if superseded.statement_date != self.statement_date:
                raise ValidationError("A correction must use the original statement date.")


class MortgagePaymentPlan(DebtManagedModel):
    """Stable parent for immutable mortgage configuration revisions."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    debt = models.OneToOneField(
        DebtAccount,
        on_delete=models.PROTECT,
        related_name="mortgage_payment_plan",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_mortgage_payment_plans",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    objects = DebtServiceManager["MortgagePaymentPlan"]()

    def __str__(self) -> str:
        return f"Mortgage plan for {self.debt_id}"

    def clean(self) -> None:
        if self.debt_id and self.debt.debt_type != DebtAccount.DebtType.MORTGAGE:
            raise ValidationError("Mortgage payment plans require a mortgage debt account.")


class MortgagePlanRevision(ImmutableDebtRecord):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    plan = models.ForeignKey(
        MortgagePaymentPlan,
        on_delete=models.PROTECT,
        related_name="revisions",
    )
    revision_number = models.PositiveIntegerField()
    effective_from = models.DateField()
    monthly_obligation = models.DecimalField(max_digits=18, decimal_places=2)
    statement_cycle_day = models.PositiveSmallIntegerField()
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_mortgage_plan_revisions",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    objects = DebtServiceManager["MortgagePlanRevision"]()

    class Meta:
        ordering = ("plan_id", "revision_number")
        constraints = [
            models.UniqueConstraint(
                fields=("plan", "revision_number"),
                name="debts_mortgage_plan_revision_unique",
            ),
            models.UniqueConstraint(
                fields=("plan", "effective_from"),
                name="debts_mortgage_plan_effective_unique",
            ),
            models.CheckConstraint(
                condition=models.Q(monthly_obligation__gt=Decimal("0")),
                name="debts_mortgage_obligation_positive",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(statement_cycle_day__gte=1) & models.Q(statement_cycle_day__lte=31)
                ),
                name="debts_mortgage_cycle_day_valid",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.plan_id} mortgage revision {self.revision_number}"


class MortgagePaymentComponent(ImmutableDebtRecord):
    class ComponentType(models.TextChoices):
        PRINCIPAL_INTEREST = "principal_interest", "Principal and interest"
        ESCROW = "escrow", "Escrow"
        PMI = "pmi", "PMI"
        FEES = "fees", "Fees"
        RECURRING_EXTRA_PRINCIPAL = (
            "recurring_extra_principal",
            "Recurring extra principal",
        )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    plan_revision = models.ForeignKey(
        MortgagePlanRevision,
        on_delete=models.PROTECT,
        related_name="components",
    )
    component_type = models.CharField(max_length=28, choices=ComponentType.choices)
    amount = models.DecimalField(max_digits=18, decimal_places=2)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_mortgage_payment_components",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    objects = DebtServiceManager["MortgagePaymentComponent"]()

    class Meta:
        ordering = ("plan_revision_id", "component_type")
        constraints = [
            models.UniqueConstraint(
                fields=("plan_revision", "component_type"),
                name="debts_mortgage_component_type_unique",
            ),
            models.CheckConstraint(
                condition=models.Q(amount__gte=Decimal("0")),
                name="debts_mortgage_component_nonnegative",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.plan_revision_id}: {self.component_type} {self.amount}"


class MortgageInstallmentRule(ImmutableDebtRecord):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    plan_revision = models.ForeignKey(
        MortgagePlanRevision,
        on_delete=models.PROTECT,
        related_name="installment_rules",
    )
    source = models.ForeignKey(
        RecurringSource,
        on_delete=models.PROTECT,
        related_name="mortgage_installment_rules",
    )
    installment_order = models.PositiveSmallIntegerField()
    amount = models.DecimalField(max_digits=18, decimal_places=2)
    day_of_month = models.PositiveSmallIntegerField()
    adjustment_policy = models.CharField(
        max_length=12,
        choices=(
            ("none", "None"),
            ("previous", "Previous"),
            ("next", "Next"),
        ),
        default="previous",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_mortgage_installment_rules",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    objects = DebtServiceManager["MortgageInstallmentRule"]()

    class Meta:
        ordering = ("plan_revision_id", "installment_order")
        constraints = [
            models.UniqueConstraint(
                fields=("plan_revision", "installment_order"),
                name="debts_mortgage_installment_order_unique",
            ),
            models.UniqueConstraint(
                fields=("plan_revision", "source"),
                name="debts_mortgage_installment_source_unique",
            ),
            models.CheckConstraint(
                condition=(models.Q(installment_order__gte=1) & models.Q(installment_order__lte=2)),
                name="debts_mortgage_installment_order_valid",
            ),
            models.CheckConstraint(
                condition=models.Q(amount__gt=Decimal("0")),
                name="debts_mortgage_installment_amount_positive",
            ),
            models.CheckConstraint(
                condition=models.Q(day_of_month__gte=1) & models.Q(day_of_month__lte=31),
                name="debts_mortgage_installment_day_valid",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.plan_revision_id}: installment {self.installment_order}"

    def clean(self) -> None:
        if self.source_id:
            if self.source.kind != RecurringSource.Kind.DEBT_PAYMENT:
                raise ValidationError("Mortgage installments require debt-payment schedules.")
            if (
                self.plan_revision_id
                and self.source.household_id != self.plan_revision.plan.debt.household_id
            ):
                raise ValidationError(
                    "The mortgage installment schedule belongs to another household."
                )
