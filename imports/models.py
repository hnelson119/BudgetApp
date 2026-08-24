from __future__ import annotations

import uuid
from decimal import Decimal

from django.conf import settings
from django.db import models

from households.models import Category, Household
from ledger.models import FinancialAccount, JournalEntry


class ImportBatch(models.Model):
    class Status(models.TextChoices):
        UPLOADED = "uploaded", "Uploaded"
        PREVIEWED = "previewed", "Previewed"
        COMMITTED = "committed", "Committed"
        ABANDONED = "abandoned", "Abandoned"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    household = models.ForeignKey(
        Household,
        on_delete=models.CASCADE,
        related_name="import_batches",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="created_import_batches",
    )
    target_account = models.ForeignKey(
        FinancialAccount,
        on_delete=models.PROTECT,
        related_name="import_batches",
    )
    original_filename = models.CharField(max_length=255)
    file_checksum = models.CharField(max_length=64)
    submission_token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    confirmation_token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.UPLOADED)
    headers = models.JSONField(default=list)
    mapping = models.JSONField(default=dict)
    staged_count = models.PositiveIntegerField(default=0)
    ready_count = models.PositiveIntegerField(default=0)
    duplicate_count = models.PositiveIntegerField(default=0)
    category_required_count = models.PositiveIntegerField(default=0)
    rejected_count = models.PositiveIntegerField(default=0)
    committed_count = models.PositiveIntegerField(default=0)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    previewed_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    raw_deleted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-uploaded_at",)
        constraints = [
            models.UniqueConstraint(
                fields=("household", "target_account", "file_checksum"),
                condition=~models.Q(status="abandoned"),
                name="imports_batch_file_account_unique",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.original_filename} · {self.get_status_display()}"


class ImportRow(models.Model):
    class Status(models.TextChoices):
        STAGED = "staged", "Staged"
        READY = "ready", "Ready"
        DUPLICATE = "duplicate", "Duplicate"
        CATEGORY_REQUIRED = "category_required", "Category required"
        REJECTED = "rejected", "Rejected"
        COMMITTED = "committed", "Committed"

    id = models.BigAutoField(primary_key=True)
    batch = models.ForeignKey(
        ImportBatch,
        on_delete=models.CASCADE,
        related_name="rows",
    )
    row_number = models.PositiveIntegerField()
    raw_data = models.JSONField(default=dict)
    effective_date = models.DateField(null=True, blank=True)
    description = models.CharField(max_length=200, blank=True)
    amount = models.DecimalField(max_digits=18, decimal_places=2, null=True, blank=True)
    category = models.ForeignKey(
        Category,
        on_delete=models.PROTECT,
        related_name="import_rows",
        null=True,
        blank=True,
    )
    fingerprint = models.CharField(max_length=64, blank=True)
    status = models.CharField(max_length=24, choices=Status.choices, default=Status.STAGED)
    rejection_reason = models.CharField(max_length=200, blank=True)
    journal_entry = models.OneToOneField(
        JournalEntry,
        on_delete=models.PROTECT,
        related_name="import_row",
        null=True,
        blank=True,
    )

    class Meta:
        ordering = ("row_number",)
        constraints = [
            models.UniqueConstraint(
                fields=("batch", "row_number"),
                name="imports_row_batch_number_unique",
            ),
            models.CheckConstraint(
                condition=models.Q(amount__isnull=True) | models.Q(amount__gt=Decimal("0.00")),
                name="imports_row_amount_positive",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.batch_id} row {self.row_number}"
