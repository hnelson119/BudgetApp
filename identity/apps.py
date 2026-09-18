from django.apps import AppConfig
from django.contrib.admin.apps import AdminConfig


class SecureAdminConfig(AdminConfig):
    default_site = "identity.admin_site.SecureAdminSite"


class IdentityConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "identity"

    def ready(self) -> None:
        from identity import signals  # noqa: F401
