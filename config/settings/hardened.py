"""Hardened settings shared by production and disposable security-test stacks."""

import os

from django.core.exceptions import ImproperlyConfigured

from .base import *  # noqa: F403
from .environment import (
    required_certificate_file,
    required_environment,
    required_private_key_file,
    required_secret_file,
)

_SETTINGS_MODULE = required_environment("DJANGO_SETTINGS_MODULE")
if _SETTINGS_MODULE not in {"config.settings.production", "config.settings.pentest"}:
    raise ImproperlyConfigured("Shared hardened settings cannot be selected directly.")

MIDDLEWARE = [*MIDDLEWARE]  # noqa: F405
MIDDLEWARE.insert(1, "core.middleware.ProxyBoundaryMiddleware")
MIDDLEWARE.insert(2, "core.middleware.HostBoundaryMiddleware")
MIDDLEWARE.insert(3, "whitenoise.middleware.WhiteNoiseMiddleware")
MIDDLEWARE.insert(
    MIDDLEWARE.index("core.middleware.AuthenticatedNoStoreMiddleware"),
    "core.middleware.OperationalEndpointBoundaryMiddleware",
)
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}
WHITENOISE_ALLOW_ALL_ORIGINS = False

SECRET_KEY = required_secret_file("DJANGO_SECRET_KEY", minimum_length=50)
MFA_ENCRYPTION_KEY = required_secret_file("DJANGO_MFA_ENCRYPTION_KEY", minimum_length=43)

required_database_values: dict[str, str] = {
    "POSTGRES_DB": required_environment("POSTGRES_DB"),
    "POSTGRES_USER": required_environment("POSTGRES_USER"),
    "DATABASE_HOST": required_environment("DATABASE_HOST"),
}
database_options = {"options": "-c search_path=public,budget_audit"}
if _SETTINGS_MODULE == "config.settings.production":
    database_options.update(
        {
            "sslmode": "verify-full",
            "sslrootcert": required_certificate_file("POSTGRES_SSL_ROOT_CERTIFICATE"),
            "sslcert": required_certificate_file("POSTGRES_SSL_CLIENT_CERTIFICATE"),
            "sslkey": required_private_key_file("POSTGRES_SSL_CLIENT_PRIVATE_KEY"),
        }
    )
else:
    required_database_values["POSTGRES_PASSWORD"] = required_secret_file("POSTGRES_PASSWORD")

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": required_database_values["POSTGRES_DB"],
        "USER": required_database_values["POSTGRES_USER"],
        "HOST": required_database_values["DATABASE_HOST"],
        "PORT": os.getenv("DATABASE_PORT", "5432"),
        "CONN_MAX_AGE": int(os.getenv("DATABASE_CONN_MAX_AGE", "60")),
        "CONN_HEALTH_CHECKS": True,
        "OPTIONS": database_options,
    }
}
if "POSTGRES_PASSWORD" in required_database_values:
    DATABASES["default"]["PASSWORD"] = required_database_values["POSTGRES_PASSWORD"]

DEBUG = False
ALLOWED_HOSTS = [host.strip() for host in required_environment("DJANGO_ALLOWED_HOSTS").split(",")]
CSRF_TRUSTED_ORIGINS = [
    origin.strip() for origin in required_environment("DJANGO_CSRF_TRUSTED_ORIGINS").split(",")
]

# Hardened processes fail during settings loading rather than silently omitting
# breached-password protection when the packaged corpus is missing, corrupt, or stale.
from identity.password_validation import (  # noqa: E402
    validate_breached_password_corpus,
)

validate_breached_password_corpus(
    BREACHED_PASSWORD_CORPUS_PATH,  # noqa: F405
    minimum_entries=BREACHED_PASSWORD_CORPUS_MINIMUM_ENTRIES,  # noqa: F405
    maximum_age_days=BREACHED_PASSWORD_CORPUS_MAXIMUM_AGE_DAYS,  # noqa: F405
    maximum_bytes=BREACHED_PASSWORD_CORPUS_MAXIMUM_BYTES,  # noqa: F405
)

SESSION_COOKIE_NAME = "__Host-budget_sessionid"
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = "Strict"
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_DOMAIN = None
SESSION_COOKIE_PATH = "/"
CSRF_COOKIE_NAME = "__Host-budget_csrftoken"
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_DOMAIN = None
CSRF_COOKIE_PATH = "/"

SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER: tuple[str, str] | None = ("HTTP_X_FORWARDED_PROTO", "https")
USE_X_FORWARDED_HOST = False
SECURE_HSTS_SECONDS = 31_536_000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
