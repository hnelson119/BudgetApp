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


class MfaCredential(models.Model):
    """Encrypted TOTP material and enrollment state for one user."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name="mfa_credential",
    )
    encrypted_secret = models.TextField(editable=False)
    key_version = models.PositiveSmallIntegerField(default=1, editable=False)
    confirmed_at = models.DateTimeField(null=True, blank=True, editable=False)
    recovery_codes_confirmed_at = models.DateTimeField(null=True, blank=True, editable=False)
    last_used_step = models.BigIntegerField(null=True, blank=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"MFA credential for {self.user_id}"


class RecoveryCode(models.Model):
    """A single-use recovery code whose secret component is irreversibly hashed."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="recovery_codes")
    identifier = models.CharField(max_length=8, unique=True, editable=False)
    code_hash = models.CharField(max_length=256, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    used_at = models.DateTimeField(null=True, blank=True, editable=False)

    class Meta:
        ordering = ("created_at",)
        indexes = [models.Index(fields=("user", "used_at"), name="recovery_code_user_state")]

    def __str__(self) -> str:
        state = "used" if self.used_at else "unused"
        return f"Recovery code {self.identifier} ({state})"
