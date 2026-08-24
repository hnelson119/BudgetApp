from __future__ import annotations

import uuid
from typing import Any
from urllib.parse import urlsplit

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from households.models import Household


class Notification(models.Model):
    class Kind(models.TextChoices):
        DUE_SOON = "due_soon", "Upcoming bill"
        OVERDUE = "overdue", "Overdue bill"
        MISSING_INCOME = "missing_income", "Missing paycheck"
        DEFICIT = "deficit", "Projected deficit"
        GOAL_MILESTONE = "goal_milestone", "Goal milestone"
        BACKUP = "backup", "Backup"
        LOGIN_ACTIVITY = "login_activity", "Login activity"
        INTEGRITY = "integrity", "Audit integrity"

    class Severity(models.TextChoices):
        INFO = "info", "Information"
        WARNING = "warning", "Warning"
        CRITICAL = "critical", "Critical"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    household = models.ForeignKey(
        Household,
        on_delete=models.CASCADE,
        related_name="notifications",
    )
    recipient = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="budget_notifications",
    )
    kind = models.CharField(max_length=24, choices=Kind.choices)
    severity = models.CharField(max_length=12, choices=Severity.choices)
    fingerprint = models.CharField(max_length=64)
    title = models.CharField(max_length=160)
    message = models.CharField(max_length=500)
    action_url = models.CharField(max_length=500, blank=True)
    source_type = models.CharField(max_length=80)
    source_id = models.CharField(max_length=80)
    occurred_at = models.DateTimeField()
    last_evaluated_at = models.DateTimeField()
    read_at = models.DateTimeField(null=True, blank=True)
    dismissed_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-occurred_at", "-created_at")
        constraints = [
            models.UniqueConstraint(
                fields=("household", "recipient", "fingerprint"),
                name="notifications_hh_recipient_fingerprint_unique",
            )
        ]
        indexes = [
            models.Index(
                fields=("household", "recipient", "dismissed_at", "resolved_at"),
                name="notifications_recipient_state",
            ),
            models.Index(
                fields=("household", "kind", "source_type", "source_id"),
                name="notifications_source_lookup",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.recipient_id}: {self.title}"

    def clean(self) -> None:
        self.title = self.title.strip()
        self.message = self.message.strip()
        self.action_url = self.action_url.strip()
        self.source_type = self.source_type.strip()
        self.source_id = self.source_id.strip()
        if not self.title or not self.message:
            raise ValidationError("Notifications require a title and message.")
        if self.action_url and not self.internal_action_url:
            raise ValidationError("Notification actions must use an internal application path.")
        if self.household_id and self.recipient_id:
            if not self.recipient.household_memberships.filter(
                household_id=self.household_id,
                is_active=True,
            ).exists():
                raise ValidationError("The notification recipient is not an active member.")

    @property
    def is_unread(self) -> bool:
        return self.read_at is None and self.dismissed_at is None

    @property
    def internal_action_url(self) -> str:
        if not self.action_url or "\\" in self.action_url:
            return ""
        parsed = urlsplit(self.action_url)
        if parsed.scheme or parsed.netloc or not parsed.path.startswith("/"):
            return ""
        return self.action_url


class NotificationPreference(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    household = models.ForeignKey(
        Household,
        on_delete=models.CASCADE,
        related_name="notification_preferences",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="notification_preferences",
    )
    due_alerts = models.BooleanField(default=True)
    missing_income_alerts = models.BooleanField(default=True)
    deficit_alerts = models.BooleanField(default=True)
    goal_alerts = models.BooleanField(default=True)
    backup_alerts = models.BooleanField(default=True)
    login_alerts = models.BooleanField(default=True)
    integrity_alerts = models.BooleanField(default=True)
    upcoming_due_days = models.PositiveSmallIntegerField(default=3)
    missing_income_grace_days = models.PositiveSmallIntegerField(default=1)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("household", "user"),
                name="notifications_preference_hh_user_unique",
            ),
            models.CheckConstraint(
                condition=models.Q(upcoming_due_days__lte=30),
                name="notifications_preference_due_days_max",
            ),
            models.CheckConstraint(
                condition=models.Q(missing_income_grace_days__lte=30),
                name="notifications_preference_income_grace_max",
            ),
        ]

    def __str__(self) -> str:
        return f"Notification preferences for {self.user_id} in {self.household_id}"

    def clean(self) -> None:
        if self.household_id and self.user_id:
            if not self.user.household_memberships.filter(
                household_id=self.household_id,
                is_active=True,
            ).exists():
                raise ValidationError("Notification preferences require active membership.")

    def as_audit_payload(self) -> dict[str, Any]:
        return {
            "due_alerts": self.due_alerts,
            "missing_income_alerts": self.missing_income_alerts,
            "deficit_alerts": self.deficit_alerts,
            "goal_alerts": self.goal_alerts,
            "backup_alerts": self.backup_alerts,
            "login_alerts": self.login_alerts,
            "integrity_alerts": self.integrity_alerts,
            "upcoming_due_days": self.upcoming_due_days,
            "missing_income_grace_days": self.missing_income_grace_days,
        }
