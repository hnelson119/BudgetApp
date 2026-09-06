"""Strict environment and file-mounted secret readers."""

import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

_MAX_SECRET_BYTES = 16 * 1024
_MAX_CERTIFICATE_BYTES = 64 * 1024
_PLACEHOLDER_MARKERS = ("change-me", "development-only", "replace-this", "example-secret")


def required_environment(name: str) -> str:
    """Return a required, non-secret environment setting."""

    value = os.getenv(name, "").strip()
    if not value:
        raise ImproperlyConfigured(f"{name} must be set in production.")
    return value


def required_secret_file(name: str, *, minimum_length: int = 32) -> str:
    """Read a production secret from NAME_FILE and reject plaintext env values."""

    if os.getenv(name):
        raise ImproperlyConfigured(
            f"{name} must not be supplied directly; mount a secret and set {name}_FILE."
        )

    file_name = os.getenv(f"{name}_FILE", "").strip()
    if not file_name:
        raise ImproperlyConfigured(f"{name}_FILE must point to a mounted secret file.")

    path = Path(file_name)
    try:
        if not path.is_file():
            raise ImproperlyConfigured(f"{name}_FILE does not identify a readable file.")
        if path.stat().st_size > _MAX_SECRET_BYTES:
            raise ImproperlyConfigured(f"{name}_FILE is unexpectedly large.")
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as error:
        raise ImproperlyConfigured(f"Unable to read {name}_FILE.") from error

    if len(value) < minimum_length:
        raise ImproperlyConfigured(
            f"{name}_FILE must contain at least {minimum_length} characters."
        )
    if any(marker in value.casefold() for marker in _PLACEHOLDER_MARKERS):
        raise ImproperlyConfigured(f"{name}_FILE contains a forbidden placeholder value.")
    return value


def required_certificate_file(name: str) -> str:
    """Return a validated mounted PEM certificate path without accepting inline material."""

    if os.getenv(name):
        raise ImproperlyConfigured(
            f"{name} must not be supplied directly; mount the certificate and set {name}_FILE."
        )
    file_name = os.getenv(f"{name}_FILE", "").strip()
    if not file_name:
        raise ImproperlyConfigured(f"{name}_FILE must point to a mounted certificate file.")
    path = Path(file_name)
    try:
        if path.is_symlink() or not path.is_file():
            raise ImproperlyConfigured(f"{name}_FILE does not identify a regular nonsymlink file.")
        size = path.stat().st_size
        if size <= 0 or size > _MAX_CERTIFICATE_BYTES:
            raise ImproperlyConfigured(f"{name}_FILE has an invalid size.")
        value = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as error:
        raise ImproperlyConfigured(f"Unable to read {name}_FILE.") from error
    if (
        value.count("-----BEGIN CERTIFICATE-----") != 1
        or value.count("-----END CERTIFICATE-----") != 1
        or not value.startswith("-----BEGIN CERTIFICATE-----")
        or not value.endswith("-----END CERTIFICATE-----")
    ):
        raise ImproperlyConfigured(f"{name}_FILE is not one PEM certificate.")
    return str(path)
