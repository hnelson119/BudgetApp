from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import User


@admin.register(User)
class HouseholdUserAdmin(UserAdmin):
    readonly_fields = (
        "session_version",
        "mfa_enrolled_at",
        "last_authenticated_at",
        "last_login",
        "date_joined",
    )
    ordering = ("email",)
    list_display = ("email", "display_name", "is_staff", "is_active", "mfa_enrolled_at")
    search_fields = ("email", "display_name", "first_name", "last_name")
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        ("Personal information", {"fields": ("display_name", "first_name", "last_name")}),
        (
            "Permissions",
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                )
            },
        ),
        (
            "Security state",
            {
                "fields": (
                    "session_version",
                    "mfa_enrolled_at",
                    "last_authenticated_at",
                    "last_login",
                    "date_joined",
                )
            },
        ),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("email", "password1", "password2", "is_staff", "is_active"),
            },
        ),
    )
