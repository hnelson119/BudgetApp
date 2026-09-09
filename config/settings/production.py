"""Production-only boundary validation for the private Linux deployment."""

import re

from django.core.exceptions import ImproperlyConfigured

from .environment import required_environment
from .hardened import *  # noqa: F403

APP_ENVIRONMENT = required_environment("APP_ENVIRONMENT")
if APP_ENVIRONMENT != "production":
    raise ImproperlyConfigured("Production settings require APP_ENVIRONMENT=production.")

_TAILSCALE_HOST = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\."
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.ts\.net$"
)
if len(ALLOWED_HOSTS) != 1 or _TAILSCALE_HOST.fullmatch(ALLOWED_HOSTS[0]) is None:  # noqa: F405
    raise ImproperlyConfigured("Production requires one exact lowercase Tailscale HTTPS hostname.")
if CSRF_TRUSTED_ORIGINS != [f"https://{ALLOWED_HOSTS[0]}"]:  # noqa: F405
    raise ImproperlyConfigured(
        "Production CSRF origins must contain only the exact Tailscale HTTPS origin."
    )

MIDDLEWARE = [*MIDDLEWARE]  # noqa: F405
MIDDLEWARE.insert(1, "core.middleware.NonBrowserTransportBoundaryMiddleware")

LOGGING["handlers"]["security_archive"] = {  # noqa: F405
    "class": "core.logging.UnixDatagramJsonHandler",
    "socket_path": "/run/security-log/security.sock",
    "formatter": "json",
    "filters": ["request_context", "security_stream"],
}
for _security_logger_name in ("security", "django.security"):
    LOGGING["loggers"][_security_logger_name]["handlers"].append("security_archive")  # noqa: F405
