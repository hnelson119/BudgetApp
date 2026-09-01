"""Verify a deployed Linux VM's private ingress without exposing sensitive state."""

from __future__ import annotations

import argparse
import http.client
import json
import re
import ssl
import sys
from pathlib import Path
from typing import Any

_PRIVATE_HOST_PATTERN = re.compile(
    r"(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\."
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.ts\.net"
)
_HSTS_POLICY = "max-age=31536000; includeSubDomains; preload"


class VerificationFailure(RuntimeError):
    pass


def _load_json(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise VerificationFailure("A private-ingress status document is malformed.")
    return document


def _contains_enabled_funnel(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, dict):
        return any(_contains_enabled_funnel(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_enabled_funnel(item) for item in value)
    return False


def validate_tailscale_status(status: dict[str, Any], hostname: str) -> int:
    self_status = status.get("Self")
    if not isinstance(self_status, dict):
        raise VerificationFailure("The Tailscale self status is missing.")
    if status.get("BackendState") != "Running" or self_status.get("Online") is not True:
        raise VerificationFailure("The private-network agent is not online.")
    dns_name = str(self_status.get("DNSName", "")).rstrip(".")
    if dns_name != hostname:
        raise VerificationFailure("The private-network hostname does not match the deployment.")
    if "tag:budget-server" not in (self_status.get("Tags") or []):
        raise VerificationFailure("The VM does not carry the dedicated server tag.")
    return 4


def validate_serve_status(status: dict[str, Any], hostname: str) -> int:
    tcp = status.get("TCP")
    web = status.get("Web")
    if tcp != {"443": {"HTTPS": True}} or not isinstance(web, dict):
        raise VerificationFailure("The private-network proxy is not HTTPS-only on port 443.")
    if set(web) != {f"{hostname}:443"}:
        raise VerificationFailure("The private-network proxy serves an unexpected hostname.")
    site = web[f"{hostname}:443"]
    if not isinstance(site, dict) or site.get("Handlers") != {
        "/": {"Proxy": "http://127.0.0.1:8000"}
    }:
        raise VerificationFailure("The private-network proxy target is not the loopback web port.")
    if _contains_enabled_funnel(status.get("AllowFunnel")):
        raise VerificationFailure("Public Funnel exposure is enabled.")
    return 4


def validate_firewall(status: str) -> int:
    normalized = status.casefold()
    if "status: active" not in normalized or "default: deny (incoming)" not in normalized:
        raise VerificationFailure("The host firewall is not active with deny-by-default ingress.")
    allow_lines = [line for line in status.splitlines() if "allow in" in line.casefold()]
    allowed_ports = {
        port for line in allow_lines for port in ("22/tcp", "443/tcp") if port in line.casefold()
    }
    if (
        allowed_ports != {"22/tcp", "443/tcp"}
        or any("tailscale0" not in line.casefold() for line in allow_lines)
        or any(
            "22/tcp" not in line.casefold() and "443/tcp" not in line.casefold()
            for line in allow_lines
        )
    ):
        raise VerificationFailure(
            "The host firewall ingress allowlist is broader than HTTPS and SSH on Tailscale."
        )
    return 3


def validate_listeners(status: str) -> int:
    local_addresses: list[str] = []
    for line in status.splitlines():
        fields = line.split()
        if len(fields) < 4:
            raise VerificationFailure("The host listener status is malformed.")
        local_addresses.append(fields[3])
    if "127.0.0.1:8000" not in local_addresses:
        raise VerificationFailure("The application is not listening on the expected loopback port.")
    for port in (5432, 2375, 2376):
        if any(address.endswith(f":{port}") for address in local_addresses):
            raise VerificationFailure("A database or Docker administration port is host-visible.")
    if any(
        address.endswith(":8000") and address != "127.0.0.1:8000" for address in local_addresses
    ):
        raise VerificationFailure("The application port is listening beyond IPv4 loopback.")
    return 5


def validate_https(hostname: str) -> int:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    connection = http.client.HTTPSConnection(hostname, 443, context=context, timeout=10)
    try:
        connection.request("GET", "/health/live/", headers={"Accept": "application/json"})
        response = connection.getresponse()
        tls_version = connection.sock.version() if connection.sock is not None else ""
        body = response.read(4097)
        if len(body) > 4096:
            raise VerificationFailure("The deployed health response was unexpectedly large.")
        if response.status != 200 or json.loads(body) != {"status": "ok"}:
            raise VerificationFailure("The deployed HTTPS health endpoint is not safe and ready.")
        if response.getheader("Strict-Transport-Security") != _HSTS_POLICY:
            raise VerificationFailure(
                "The deployed HTTPS response lost the production HSTS policy."
            )
        if tls_version not in {"TLSv1.2", "TLSv1.3"}:
            raise VerificationFailure("The deployed connection negotiated an obsolete TLS version.")
    finally:
        connection.close()
    return 4


def validate_plain_http(hostname: str) -> int:
    connection = http.client.HTTPConnection(hostname, 80, timeout=5)
    try:
        connection.request("GET", "/health/live/")
        response = connection.getresponse()
        body = response.read(4097)
        if len(body) > 4096:
            raise VerificationFailure("The deployed HTTP response was unexpectedly large.")
        if response.status not in {301, 302, 307, 308} or response.getheader("Location") != (
            f"https://{hostname}/health/live/"
        ):
            raise VerificationFailure(
                "Plain HTTP served content instead of an exact HTTPS redirect."
            )
    except (TimeoutError, ConnectionError, OSError):
        return 1
    finally:
        connection.close()
    return 2


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--tailscale-status", type=Path, required=True)
    parser.add_argument("--serve-status", type=Path, required=True)
    parser.add_argument("--ufw-status", type=Path, required=True)
    parser.add_argument("--listeners", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    arguments = parse_arguments()
    try:
        if _PRIVATE_HOST_PATTERN.fullmatch(arguments.hostname) is None:
            raise VerificationFailure("The expected private-network hostname is invalid.")
        private_checks = validate_tailscale_status(
            _load_json(arguments.tailscale_status), arguments.hostname
        )
        proxy_checks = validate_serve_status(_load_json(arguments.serve_status), arguments.hostname)
        firewall_checks = validate_firewall(arguments.ufw_status.read_text(encoding="utf-8"))
        listener_checks = validate_listeners(arguments.listeners.read_text(encoding="utf-8"))
        tls_checks = validate_https(arguments.hostname)
        http_checks = validate_plain_http(arguments.hostname)
    except (VerificationFailure, OSError, UnicodeError, ValueError):
        print("Private-ingress verification failed safely.", file=sys.stderr)
        raise SystemExit(1) from None

    print(
        "Linux VM private-ingress controls passed "
        f"({private_checks + proxy_checks + firewall_checks + listener_checks} boundary checks)."
    )
    print(f"NET-03 deployment controls passed ({tls_checks + http_checks} transport checks).")
    print("Funnel is disabled; the application remains private-network only.")
    print("NET-01 and NET-02 still require the documented two-device release procedure.")


if __name__ == "__main__":
    main()
