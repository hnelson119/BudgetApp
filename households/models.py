import uuid
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import models
from django.db.models.functions import Lower


class Household(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=120)
    currency = models.CharField(max_length=3, default="USD")
    time_zone = models.CharField(max_length=64, default="America/New_York")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)

    def __str__(self) -> str:
        return self.name


class HouseholdMembership(models.Model):
    """Equal application access for each person in a shared household."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    household = models.ForeignKey(
        Household,
        on_delete=models.CASCADE,
        related_name="memberships",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="household_memberships",
    )
    is_active = models.BooleanField(default=True)
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("household", "user"),
                name="households_membership_household_user_unique",
            )
        ]
        ordering = ("joined_at",)

    def __str__(self) -> str:
        return f"{self.user} · {self.household}"


class Category(models.Model):
    """A household-defined spending category; archived categories retain history."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    household = models.ForeignKey(
        Household,
        on_delete=models.CASCADE,
        related_name="categories",
    )
    name = models.CharField(max_length=80)
    color = models.CharField(
        max_length=7,
        default="#64748B",
        validators=[RegexValidator(r"^#[0-9A-Fa-f]{6}$", "Use a six-digit hex color.")],
    )
    sort_order = models.PositiveIntegerField(default=0)
    is_archived = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("is_archived", "sort_order", "name")
        constraints = [
            models.UniqueConstraint(
                models.F("household"),
                Lower("name"),
                name="households_category_hh_name_ci_unique",
            )
        ]

    def __str__(self) -> str:
        return f"{self.household}: {self.name}"

    def save(self, *args: Any, **kwargs: Any) -> None:
        self.name = self.name.strip()
        self.color = self.color.upper()
        super().save(*args, **kwargs)

    def clean(self) -> None:
        self.name = self.name.strip()
        self.color = self.color.upper()
        if not self.name:
            raise ValidationError({"name": "Category name is required."})
