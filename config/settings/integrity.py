"""Settings for the isolated, non-HTTP audit-integrity process."""

from .base import *  # noqa: F403
from .environment import required_environment, required_secret_file

SECRET_KEY = required_secret_file("AUDIT_CHECKPOINT_SIGNING_KEY", minimum_length=43)

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": required_environment("POSTGRES_DB"),
        "USER": required_environment("POSTGRES_USER"),
        "PASSWORD": required_secret_file("POSTGRES_PASSWORD"),
        "HOST": required_environment("DATABASE_HOST"),
        "PORT": required_environment("DATABASE_PORT"),
        "CONN_MAX_AGE": 0,
        "OPTIONS": {"options": "-c search_path=public,budget_audit"},
    }
}
