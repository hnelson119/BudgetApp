from __future__ import annotations

import uuid
from collections.abc import Collection, Iterable
from decimal import Decimal
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from households.models import Household
from ledger.models import FinancialAccount, JournalEntry
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


class CardPaymentReserveEntryQuerySet(models.QuerySet["CardPaymentReserveEntry"]):
    def create(self, **kwargs: Any) -> CardPaymentReserveEntry:
        raise ValidationError("Card-payment reserve entries must use a spending service.")

    def delete(self) -> tuple[int, dict[str, int]]:
        raise ValidationError("Card-payment reserve entries cannot be deleted.")

    def update(self, **kwargs: Any) -> int:
        raise ValidationError("Card-payment reserve entries cannot be updated.")

    def bulk_create(
        self,
        objs: Iterable[CardPaymentReserveEntry],
        batch_size: int | None = None,
        ignore_conflicts: bool = False,
        update_conflicts: bool = False,
        update_fields: Collection[str] | None = None,
        unique_fields: Collection[str] | None = None,
    ) -> list[CardPaymentReserveEntry]:
        raise ValidationError("Card-payment reserve entries must use a spending service.")

    def bulk_update(
        self,
        objs: Iterable[CardPaymentReserveEntry],
        fields: Iterable[str],
        batch_size: int | None = None,
    ) -> int:
        raise ValidationError("Card-payment reserve entries cannot be updated.")


class CardPaymentReserveEntryManager(models.Manager["CardPaymentReserveEntry"]):
    def get_queryset(self) -> CardPaymentReserveEntryQuerySet:
        return CardPaymentReserveEntryQuerySet(self.model, using=self._db)

    def create(self, **kwargs: Any) -> CardPaymentReserveEntry:
        raise ValidationError("Card-payment reserve entries must use a spending service.")


class CardPaymentReserveEntry(models.Model):
    """Append-only allocation history for cash reserved to settle card purchases."""

    class EntryType(models.TextChoices):
        PURCHASE = "purchase", "Categorized purchase"
        PURCHASE_REVERSAL = "purchase_reversal", "Purchase refund or reversal"
        PAYMENT = "payment", "Card payment allocation"
        PAYMENT_REVERSAL = "payment_reversal", "Card payment reversal"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    household = models.ForeignKey(
        Household,
        on_delete=models.PROTECT,
        related_name="card_payment_reserve_entries",
    )
    pay_period = models.ForeignKey(
        PayPeriod,
        on_delete=models.PROTECT,
        related_name="card_payment_reserve_entries",
    )
    card_account = models.ForeignKey(
        FinancialAccount,
        on_delete=models.PROTECT,
        related_name="payment_reserve_entries",
    )
    journal_entry = models.OneToOneField(
        JournalEntry,
        on_delete=models.PROTECT,
        related_name="card_payment_reserve_entry",
    )
    entry_type = models.CharField(max_length=24, choices=EntryType.choices)
    amount = models.DecimalField(max_digits=18, decimal_places=2)
    payment_amount = models.DecimalField(max_digits=18, decimal_places=2, default=Decimal("0.00"))
    reserve_settlement = models.DecimalField(
        max_digits=18,
        decimal_places=2,
        default=Decimal("0.00"),
    )
    debt_payoff = models.DecimalField(max_digits=18, decimal_places=2, default=Decimal("0.00"))
    purchase_refund_amount = models.DecimalField(
        max_digits=18,
        decimal_places=2,
        default=Decimal("0.00"),
    )
    neutral_correction = models.DecimalField(
        max_digits=18,
        decimal_places=2,
        default=Decimal("0.00"),
    )
    reason = models.CharField(max_length=500, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_card_payment_reserve_entries",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    objects = CardPaymentReserveEntryManager()

    class Meta:
        ordering = ("created_at", "id")
        indexes = [
            models.Index(
                fields=("card_account", "created_at"),
                name="reserves_card_account_time",
            ),
            models.Index(
                fields=("household", "pay_period"),
                name="reserves_card_hh_period",
            ),
        ]
        constraints = [
            models.CheckConstraint(
                condition=(
                    models.Q(payment_amount__gte=Decimal("0.00"))
                    & models.Q(reserve_settlement__gte=Decimal("0.00"))
                    & models.Q(debt_payoff__gte=Decimal("0.00"))
                    & models.Q(purchase_refund_amount__gte=Decimal("0.00"))
                    & models.Q(neutral_correction__gte=Decimal("0.00"))
                ),
                name="reserves_card_amounts_nonnegative",
            ),
            models.CheckConstraint(
                condition=(
                    models.Q(
                        entry_type="purchase",
                        amount__gt=Decimal("0.00"),
                        payment_amount=Decimal("0.00"),
                        reserve_settlement=Decimal("0.00"),
                        debt_payoff=Decimal("0.00"),
                        purchase_refund_amount=Decimal("0.00"),
                        neutral_correction=Decimal("0.00"),
                    )
                    | models.Q(
                        entry_type="purchase_reversal",
                        amount__lte=Decimal("0.00"),
                        purchase_refund_amount__gt=Decimal("0.00"),
                        payment_amount=Decimal("0.00"),
                        reserve_settlement=Decimal("0.00"),
                        debt_payoff=Decimal("0.00"),
                        neutral_correction=Decimal("0.00"),
                    )
                    | models.Q(
                        entry_type="payment",
                        amount=-models.F("reserve_settlement"),
                        payment_amount=models.F("reserve_settlement")
                        + models.F("debt_payoff")
                        + models.F("neutral_correction"),
                        payment_amount__gt=Decimal("0.00"),
                        purchase_refund_amount=Decimal("0.00"),
                        neutral_correction=Decimal("0.00"),
                    )
                    | models.Q(
                        entry_type="payment_reversal",
                        amount=models.F("reserve_settlement"),
                        payment_amount=models.F("reserve_settlement")
                        + models.F("debt_payoff")
                        + models.F("neutral_correction"),
                        payment_amount__gt=Decimal("0.00"),
                        purchase_refund_amount=Decimal("0.00"),
                    )
                ),
                name="reserves_card_entry_type_amounts_valid",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.card_account_id}: {self.amount} ({self.entry_type})"

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not getattr(self, "_service_authorized", False):
            raise ValidationError("Card-payment reserve entries must use a spending service.")
        if not self._state.adding:
            raise ValidationError("Card-payment reserve entries cannot be updated.")
        self.reason = self.reason.strip()
        super().save(*args, force_insert=True, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError("Card-payment reserve entries cannot be deleted.")

    def clean(self) -> None:
        super().clean()
        if self.card_account_id is not None:
            if self.card_account.household_id != self.household_id:
                raise ValidationError("The card account belongs to another household.")
            if (
                self.card_account.account_type != FinancialAccount.AccountType.CREDIT_CARD
                or self.card_account.classification != FinancialAccount.Classification.LIABILITY
            ):
                raise ValidationError("The reserve account must be a credit-card liability.")
        if self.pay_period_id is not None and self.pay_period.household_id != self.household_id:
            raise ValidationError("The paycheck period belongs to another household.")
        if (
            self.journal_entry_id is not None
            and self.journal_entry.household_id != self.household_id
        ):
            raise ValidationError("The journal entry belongs to another household.")
