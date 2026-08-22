"""Hardened settings for the private Linux deployment."""

import os

from .base import *  # noqa: F403
from .environment import required_environment, required_secret_file

MIDDLEWARE = [*MIDDLEWARE]  # noqa: F405
MIDDLEWARE.insert(1, "whitenoise.middleware.WhiteNoiseMiddleware")
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}

SECRET_KEY = required_secret_file("DJANGO_SECRET_KEY", minimum_length=50)
MFA_ENCRYPTION_KEY = required_secret_file("DJANGO_MFA_ENCRYPTION_KEY", minimum_length=43)

required_database_values = {
    "POSTGRES_DB": required_environment("POSTGRES_DB"),
    "POSTGRES_USER": required_environment("POSTGRES_USER"),
    "POSTGRES_PASSWORD": required_secret_file("POSTGRES_PASSWORD"),
    "DATABASE_HOST": required_environment("DATABASE_HOST"),
}

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": required_database_values["POSTGRES_DB"],
        "USER": required_database_values["POSTGRES_USER"],
        "PASSWORD": required_database_values["POSTGRES_PASSWORD"],
        "HOST": required_database_values["DATABASE_HOST"],
        "PORT": os.getenv("DATABASE_PORT", "5432"),
        "CONN_MAX_AGE": int(os.getenv("DATABASE_CONN_MAX_AGE", "60")),
        "CONN_HEALTH_CHECKS": True,
    }
}

DEBUG = False
ALLOWED_HOSTS = [host.strip() for host in required_environment("DJANGO_ALLOWED_HOSTS").split(",")]
CSRF_TRUSTED_ORIGINS = [
    origin.strip() for origin in required_environment("DJANGO_CSRF_TRUSTED_ORIGINS").split(",")
]

SESSION_COOKIE_NAME = "__Host-budget_sessionid"
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_SAMESITE = "Strict"
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
CSRF_COOKIE_NAME = "__Host-budget_csrftoken"
CSRF_COOKIE_SECURE = True
CSRF_COOKIE_SAMESITE = "Strict"

SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_HSTS_SECONDS = 31_536_000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
