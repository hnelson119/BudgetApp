"""Settings shared by every environment."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]


def env_list(name: str, default: str = "") -> list[str]:
    return [value.strip() for value in os.getenv(name, default).split(",") if value.strip()]


SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "unsafe-development-key-change-before-deploying")
DEBUG = False
ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "core.apps.CoreConfig",
    "identity.apps.IdentityConfig",
    "households.apps.HouseholdsConfig",
    "schedules.apps.SchedulesConfig",
    "periods.apps.PeriodsConfig",
    "ledger.apps.LedgerConfig",
    "budgets.apps.BudgetsConfig",
    "spending.apps.SpendingConfig",
    "imports.apps.ImportsConfig",
    "debts.apps.DebtsConfig",
    "goals.apps.GoalsConfig",
    "reserves.apps.ReservesConfig",
    "audit.apps.AuditConfig",
    "notifications.apps.NotificationsConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "core.middleware.RequestContextMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "identity.middleware.SecureSessionMiddleware",
    "core.middleware.ActorContextMiddleware",
    "core.middleware.AuthenticatedNoStoreMiddleware",
    "core.middleware.ContentSecurityPolicyMiddleware",
    "core.middleware.ExceptionLoggingMiddleware",
    "identity.middleware.MfaRequiredMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "notifications.context_processors.notification_badge",
            ],
        },
    }
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

AUTH_USER_MODEL = "identity.User"

LANGUAGE_CODE = "en-us"
TIME_ZONE = os.getenv("DJANGO_TIME_ZONE", "America/New_York")
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/accounts/login/"

# A session can live for twelve hours, with a shorter idle timeout enforced by
# application middleware in the authentication milestone.
SESSION_COOKIE_AGE = 60 * 60 * 12
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Strict"
SESSION_IDLE_TIMEOUT_SECONDS = 60 * 60
SESSION_ABSOLUTE_TIMEOUT_SECONDS = 60 * 60 * 12
SESSION_ACTIVITY_UPDATE_SECONDS = 60

LOGIN_RATE_LIMIT_FAILURES = 5
LOGIN_RATE_LIMIT_WINDOW_SECONDS = 15 * 60
LOGIN_RATE_LIMIT_BLOCK_SECONDS = 15 * 60

MFA_ENCRYPTION_KEY = os.getenv(
    "DJANGO_MFA_ENCRYPTION_KEY",
    "unsafe-development-mfa-key-not-for-production",
)
MFA_ENCRYPTION_KEY_VERSION = 1
MFA_ISSUER = "Household Budget"
MFA_PENDING_TIMEOUT_SECONDS = 5 * 60
MFA_TOTP_PERIOD_SECONDS = 30
MFA_TOTP_CLOCK_DRIFT_STEPS = 1
MFA_RECOVERY_CODE_COUNT = 10
RECENT_AUTH_TIMEOUT_SECONDS = 10 * 60

DATA_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024
FILE_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024
CSV_IMPORT_MAX_BYTES = 5 * 1024 * 1024
CSV_IMPORT_MAX_ROWS = 10_000
CSV_IMPORT_MAX_COLUMNS = 50
CSV_IMPORT_MAX_CELL_LENGTH = 1_000

X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {"()": "core.logging.RedactingJsonFormatter"},
    },
    "filters": {
        "request_context": {"()": "core.logging.RequestContextFilter"},
        "security_stream": {"()": "core.logging.SecurityStreamFilter"},
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
            "filters": ["request_context"],
        },
        "security_console": {
            "class": "logging.StreamHandler",
            "formatter": "json",
            "filters": ["request_context", "security_stream"],
        },
        "null": {"class": "logging.NullHandler"},
    },
    "loggers": {
        "security": {
            "handlers": ["security_console"],
            "level": "INFO",
            "propagate": False,
        },
        "django.security": {
            "handlers": ["security_console"],
            "level": "WARNING",
            "propagate": False,
        },
        "django.request": {
            "handlers": ["null"],
            "level": "CRITICAL",
            "propagate": False,
        },
    },
    "root": {
        "handlers": ["console"],
        "level": os.getenv("DJANGO_LOG_LEVEL", "INFO"),
    },
}
