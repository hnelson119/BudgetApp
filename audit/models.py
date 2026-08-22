import uuid
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from households.models import Household

ZERO_HASH = "0" * 64


class ImmutableAuditQuerySet(models.QuerySet["AuditEvent"]):
    def create(self, **kwargs: Any) -> "AuditEvent":
        raise ValidationError("Audit events must use the append service.")

    def delete(self) -> tuple[int, dict[str, int]]:
        raise ValidationError("Audit events cannot be deleted.")

    def update(self, **kwargs: Any) -> int:
        raise ValidationError("Audit events cannot be updated.")

    def bulk_create(self, *args: Any, **kwargs: Any) -> list["AuditEvent"]:
        raise ValidationError("Audit events must use the append service.")

    def bulk_update(self, *args: Any, **kwargs: Any) -> int:
        raise ValidationError("Audit events cannot be updated.")


class ImmutableAuditManager(models.Manager["AuditEvent"]):
    def get_queryset(self) -> ImmutableAuditQuerySet:
        return ImmutableAuditQuerySet(self.model, using=self._db)

    def create(self, **kwargs: Any) -> "AuditEvent":
        raise ValidationError("Audit events must use the append service.")


class AuditHead(models.Model):
    household = models.OneToOneField(
        Household,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="audit_head",
    )
    last_sequence = models.PositiveBigIntegerField(default=0)
    event_count = models.PositiveBigIntegerField(default=0)
    chain_head = models.CharField(max_length=64, default=ZERO_HASH)
    verified_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"Audit head for {self.household_id}"


class AuditEvent(models.Model):
    sequence = models.PositiveBigIntegerField()
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    household = models.ForeignKey(Household, on_delete=models.PROTECT, related_name="audit_events")
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="audit_events",
        null=True,
        blank=True,
    )
    occurred_at = models.DateTimeField()
    household_timezone = models.CharField(max_length=64)
    action = models.CharField(max_length=80)
    entity_type = models.CharField(max_length=80)
    entity_id = models.CharField(max_length=64)
    before_payload = models.JSONField(default=dict)
    after_payload = models.JSONField(default=dict)
    reason = models.CharField(max_length=500, blank=True)
    request_id = models.CharField(max_length=64)
    previous_hash = models.CharField(max_length=64)
    event_hash = models.CharField(max_length=64)

    objects = ImmutableAuditManager()

    class Meta:
        ordering = ("household_id", "sequence")
        default_permissions = ()
        constraints = [
            models.UniqueConstraint(
                fields=("household", "sequence"),
                name="audit_event_household_sequence_unique",
            )
        ]
        indexes = [
            models.Index(fields=("household", "occurred_at"), name="audit_event_household_time")
        ]

    def __str__(self) -> str:
        return f"{self.household_id}:{self.sequence}:{self.action}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not getattr(self, "_append_authorized", False):
            raise ValidationError("Audit events must use the append service.")
        if not self._state.adding:
            raise ValidationError("Audit events cannot be updated.")
        super().save(*args, force_insert=True, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError("Audit events cannot be deleted.")


class ImmutableCheckpointQuerySet(models.QuerySet["AuditCheckpoint"]):
    def create(self, **kwargs: Any) -> "AuditCheckpoint":
        raise ValidationError("Audit checkpoints must use the checkpoint service.")

    def delete(self) -> tuple[int, dict[str, int]]:
        raise ValidationError("Audit checkpoints cannot be deleted.")

    def update(self, **kwargs: Any) -> int:
        raise ValidationError("Audit checkpoints cannot be updated.")

    def bulk_create(self, *args: Any, **kwargs: Any) -> list["AuditCheckpoint"]:
        raise ValidationError("Audit checkpoints must use the checkpoint service.")

    def bulk_update(self, *args: Any, **kwargs: Any) -> int:
        raise ValidationError("Audit checkpoints cannot be updated.")


class ImmutableCheckpointManager(models.Manager["AuditCheckpoint"]):
    def get_queryset(self) -> ImmutableCheckpointQuerySet:
        return ImmutableCheckpointQuerySet(self.model, using=self._db)

    def create(self, **kwargs: Any) -> "AuditCheckpoint":
        raise ValidationError("Audit checkpoints must use the checkpoint service.")


class AuditCheckpoint(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    household = models.ForeignKey(
        Household,
        on_delete=models.PROTECT,
        related_name="audit_checkpoints",
    )
    last_sequence = models.PositiveBigIntegerField()
    event_count = models.PositiveBigIntegerField()
    chain_head = models.CharField(max_length=64)
    verified_at = models.DateTimeField()
    signature_algorithm = models.CharField(max_length=32)
    signing_key_id = models.CharField(max_length=64)
    signature = models.CharField(max_length=64)
    external_copy_name = models.CharField(max_length=255)
    external_copied_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    objects = ImmutableCheckpointManager()

    class Meta:
        ordering = ("-verified_at",)
        default_permissions = ()
        indexes = [
            models.Index(
                fields=("household", "verified_at"),
                name="audit_checkpoint_hh_time",
            )
        ]

    def __str__(self) -> str:
        return f"{self.household_id}:{self.last_sequence}:{self.verified_at.isoformat()}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        if not getattr(self, "_append_authorized", False):
            raise ValidationError("Audit checkpoints must use the checkpoint service.")
        if not self._state.adding:
            raise ValidationError("Audit checkpoints cannot be updated.")
        super().save(*args, force_insert=True, **kwargs)

    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        raise ValidationError("Audit checkpoints cannot be deleted.")
