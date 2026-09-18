"""Gunicorn's authenticated internal TLS boundary for production Compose."""

from __future__ import annotations

import ssl
from collections.abc import Callable
from typing import Any

bind = "0.0.0.0:8443"
certfile = "/run/secrets/gunicorn_server_certificate"
keyfile = "/run/secrets/gunicorn_server_private_key"
ca_certs = "/run/secrets/gunicorn_client_ca_certificate"
cert_reqs = ssl.CERT_REQUIRED
timeout = 30
graceful_timeout = 30


def ssl_context(
    _configuration: Any,
    default_ssl_context_factory: Callable[[], ssl.SSLContext],
) -> ssl.SSLContext:
    """Allow only the explicitly supported internal TLS protocol versions."""

    context = default_ssl_context_factory()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    return context
