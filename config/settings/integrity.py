"""Settings for the isolated, non-HTTP audit-integrity process."""

import os

from .base import *  # noqa: F403
from .environment import required_certificate_file, required_environment, required_secret_file

SECRET_KEY = required_secret_file("AUDIT_CHECKPOINT_SIGNING_KEY", minimum_length=43)
database_options = {"options": "-c search_path=public,budget_audit"}
if os.getenv("APP_ENVIRONMENT") == "production":
    database_options.update(
        {
            "sslmode": "verify-full",
            "sslrootcert": required_certificate_file("POSTGRES_SSL_ROOT_CERTIFICATE"),
        }
    )

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": required_environment("POSTGRES_DB"),
        "USER": required_environment("POSTGRES_USER"),
        "PASSWORD": required_secret_file("POSTGRES_PASSWORD"),
        "HOST": required_environment("DATABASE_HOST"),
        "PORT": required_environment("DATABASE_PORT"),
        "CONN_MAX_AGE": 0,
        "OPTIONS": database_options,
    }
}
