import uuid
from typing import Any, ClassVar

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.db.models.functions import Lower

from .managers import UserManager


class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = None  # type: ignore[assignment]
    email = models.EmailField(unique=True)
    display_name = models.CharField(max_length=100, blank=True)
    session_version = models.PositiveBigIntegerField(default=1, editable=False)
    mfa_enrolled_at = models.DateTimeField(null=True, blank=True, editable=False)
    last_authenticated_at = models.DateTimeField(null=True, blank=True, editable=False)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS: ClassVar[list[str]] = []

    objects: ClassVar[UserManager] = UserManager()

    class Meta:
        constraints = [
            models.UniqueConstraint(Lower("email"), name="identity_user_email_ci_unique")
        ]

    def save(self, *args: Any, **kwargs: Any) -> None:
        self.email = self.email.strip().lower()
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return self.email


class LoginThrottle(models.Model):
    """HMAC-pseudonymized counters used to slow password guessing."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    key_hash = models.CharField(max_length=64, unique=True, editable=False)
    window_started_at = models.DateTimeField()
    failure_count = models.PositiveSmallIntegerField(default=0)
    blocked_until = models.DateTimeField(null=True, blank=True)
    last_failure_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("window_started_at",)

    def __str__(self) -> str:
        return f"Login throttle {self.key_hash[:8]}"
