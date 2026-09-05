"""Inspect a disposable production Compose stack without printing sensitive state."""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

_EXPECTED_SECRETS = {
    "django_secret_key",
    "django_mfa_encryption_key",
    "postgres_runtime_password",
}
_REQUIRED_SECRET_NAMES = {
    *_EXPECTED_SECRETS,
    "postgres_admin_password",
    "postgres_migration_password",
    "postgres_backup_password",
    "postgres_audit_password",
    "audit_checkpoint_signing_key",
    "restic_repository_password",
}
_SECRET_FILES = {
    **{name: name for name in _REQUIRED_SECRET_NAMES},
    "django_mfa_encryption_key_next": "django_mfa_encryption_key.next",
    "postgres_admin_password_next": (  # pragma: allowlist secret
        "postgres_admin_password.next"
    ),
    "restic_repository_password_next": (  # pragma: allowlist secret
        "restic_repository_password.next"
    ),
}
_ALL_SECRET_NAMES = set(_SECRET_FILES)
_SECRET_BEARING_SERVICES = {
    "backup",
    "db",
    "db-admin-key-rotate",
    "db-bootstrap",
    "import-cleanup",
    "integrity",
    "mfa-key-rotate",
    "migrate",
    "notify",
    "restic-key-rotate",
    "restore-verify",
    "web",
}
_EXPECTED_SERVICE_NETWORKS = {
    "backup": {"backend"},
    "db": {"backend"},
    "db-admin-key-rotate": {"backend"},
    "db-bootstrap": {"backend"},
    "import-cleanup": {"backend"},
    "ingress": {"frontend", "ingress"},
    "integrity": {"backend"},
    "mfa-key-rotate": {"backend"},
    "migrate": {"backend"},
    "notify": {"backend"},
    "restic-key-rotate": set(),
    "restore-verify": {"backend"},
    "security-log": set(),
    "web": {"backend", "frontend"},
}
_NETWORK_BYPASS_KEYS = {
    "cap_add",
    "device_cgroup_rules",
    "devices",
    "dns",
    "dns_search",
    "external_links",
    "extra_hosts",
    "links",
    "privileged",
}
_FORBIDDEN_ENVIRONMENT_NAMES = {
    "DJANGO_SECRET_KEY",
    "DJANGO_MFA_ENCRYPTION_KEY",
    "POSTGRES_PASSWORD",
    "POSTGRES_ADMIN_PASSWORD",
    "POSTGRES_MIGRATION_PASSWORD",
    "POSTGRES_BACKUP_PASSWORD",
    "POSTGRES_AUDIT_PASSWORD",
    "AUDIT_CHECKPOINT_SIGNING_KEY",
    "RESTIC_PASSWORD",
}
_MAXIMUM_RESPONSE_SIZE = 1024 * 1024
_MAXIMUM_RAW_REQUEST_SIZE = 64 * 1024
_HTTP_STATUS_LINE = re.compile(rb"(?m)^HTTP/1\.[01] ([1-5][0-9]{2})")
_EXPECTED_PROXY_DESTINATION = "proxy_pass http://web:8000;"


class ProbeFailure(RuntimeError):
    pass


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(  # type: ignore[no-untyped-def]
        self, request, file_pointer, code, message, headers, new_url
    ):
        return None


def _run(command: list[str], *, timeout: int = 120) -> str:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise ProbeFailure("A bounded production-boundary inspection command failed.")
    return result.stdout


def _run_expect_failure(command: list[str], *, timeout: int = 30) -> None:
    result = subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=timeout,
        check=False,
    )
    if result.returncode == 0:
        raise ProbeFailure("A prohibited production-boundary operation unexpectedly succeeded.")


def _compose_prefix(compose_file: Path, project_name: str) -> list[str]:
    return ["docker", "compose", "-p", project_name, "-f", str(compose_file)]


def _references(items: Any) -> set[str]:
    references: set[str] = set()
    for item in items or []:
        if isinstance(item, str):
            references.add(item)
        elif isinstance(item, dict) and isinstance(item.get("source"), str):
            references.add(item["source"])
        else:
            raise ProbeFailure("A Compose resource reference is malformed.")
    return references


def _network_names(value: Any) -> set[str]:
    if isinstance(value, list):
        return {str(item) for item in value}
    if isinstance(value, dict):
        return {str(item) for item in value}
    raise ProbeFailure("A Compose network reference is malformed.")


def validate_relay_destination(configuration: str) -> int:
    outbound_directives = [
        line.strip()
        for line in configuration.splitlines()
        if re.match(r"^(?:fastcgi|grpc|memcached|proxy|scgi|uwsgi)_pass(?:\s|$)", line.strip())
    ]
    if outbound_directives != [_EXPECTED_PROXY_DESTINATION] or any(
        line.strip().startswith(("include ", "resolver ")) for line in configuration.splitlines()
    ):
        raise ProbeFailure("The loopback relay destination does not match the internal allowlist.")
    return 1


def validate_compose_boundary(configuration: dict[str, Any]) -> int:
    services = configuration.get("services")
    networks = configuration.get("networks")
    if not isinstance(services, dict) or not isinstance(networks, dict):
        raise ProbeFailure("The production Compose model is incomplete.")
    if set(networks) != {"ingress", "frontend", "backend"} or not all(
        isinstance(networks.get(name), dict) for name in networks
    ):
        raise ProbeFailure("Production Docker networks do not match the network allowlist.")
    if not all(networks[name].get("internal") is True for name in ("frontend", "backend")):
        raise ProbeFailure("Application and database networks are not internal-only.")
    if networks["ingress"].get("internal") is True:
        raise ProbeFailure("The loopback relay network cannot publish a host port.")
    if networks["ingress"].get("external") is True:
        raise ProbeFailure("The loopback relay uses an unmanaged Docker network.")
    if set(services) != set(_EXPECTED_SERVICE_NETWORKS):
        raise ProbeFailure("The production service catalog does not match the network allowlist.")

    for service_name, expected_networks in _EXPECTED_SERVICE_NETWORKS.items():
        service = services[service_name]
        if not isinstance(service, dict):
            raise ProbeFailure("A production Compose service is malformed.")
        if any(key in service for key in _NETWORK_BYPASS_KEYS):
            raise ProbeFailure("A production service declares a prohibited network bypass.")
        if not expected_networks:
            if service.get("network_mode") != "none" or service.get("networks"):
                raise ProbeFailure("An offline production service gained network access.")
        elif (
            "network_mode" in service
            or _network_names(service.get("networks")) != expected_networks
        ):
            raise ProbeFailure("A production service has an unexpected network attachment.")

    published: list[tuple[str, Any]] = []
    for service_name, service in services.items():
        assert isinstance(service, dict)
        for port in service.get("ports", []) or []:
            published.append((str(service_name), port))
    if len(published) != 1 or published[0][0] != "ingress":
        raise ProbeFailure("Production publishes a service other than the loopback relay.")
    port = published[0][1]
    if not isinstance(port, dict) or (
        port.get("host_ip"),
        str(port.get("published")),
        port.get("target"),
        port.get("protocol"),
    ) != ("127.0.0.1", "8000", 8000, "tcp"):
        raise ProbeFailure("The web service is not published only on loopback port 8000.")

    web = services.get("web")
    database = services.get("db")
    ingress = services.get("ingress")
    if not all(isinstance(service, dict) for service in (web, database, ingress)):
        raise ProbeFailure("The production runtime services are missing.")
    assert isinstance(web, dict)
    assert isinstance(database, dict)
    assert isinstance(ingress, dict)
    if _network_names(web.get("networks")) != {"frontend", "backend"}:
        raise ProbeFailure("The web service has an unexpected Docker network attachment.")
    if _network_names(database.get("networks")) != {"backend"} or database.get("ports"):
        raise ProbeFailure("PostgreSQL is not isolated on the internal backend network.")
    if _network_names(ingress.get("networks")) != {"ingress", "frontend"}:
        raise ProbeFailure("The secretless relay has an unexpected Docker network attachment.")
    if web.get("ports") or ingress.get("secrets"):
        raise ProbeFailure("The web publish or relay secret boundary is invalid.")
    if _references(web.get("secrets")) != _EXPECTED_SECRETS:
        raise ProbeFailure("The web service receives an unexpected secret set.")
    environment = web.get("environment")
    if not isinstance(environment, dict) or (
        str(environment.get("DATABASE_HOST")),
        str(environment.get("DATABASE_PORT")),
    ) != ("db", "5432"):
        raise ProbeFailure("The web service database destination is outside the allowlist.")
    if (
        str(web.get("user")) != "10001:10001"
        or web.get("read_only") is not True
        or web.get("cap_drop") != ["ALL"]
        or web.get("pids_limit") != 128
        or "no-new-privileges:true" not in (web.get("security_opt") or [])
    ):
        raise ProbeFailure("The web service is missing a runtime hardening control.")
    if (
        str(ingress.get("user")) != "101:101"
        or ingress.get("read_only") is not True
        or ingress.get("cap_drop") != ["ALL"]
        or ingress.get("pids_limit") != 64
        or "no-new-privileges:true" not in (ingress.get("security_opt") or [])
    ):
        raise ProbeFailure("The loopback relay is missing a runtime hardening control.")
    return 18 + len(_EXPECTED_SERVICE_NETWORKS)


def validate_secret_sources(configuration: dict[str, Any], secret_directory: Path) -> int:
    secrets = configuration.get("secrets")
    if not isinstance(secrets, dict) or set(secrets) != _ALL_SECRET_NAMES:
        raise ProbeFailure("The Compose secret catalog does not match the production allowlist.")
    for name in sorted(_ALL_SECRET_NAMES):
        secret = secrets[name]
        if (
            not isinstance(secret, dict)
            or not isinstance(secret.get("file"), str)
            or secret.get("external") is True
            or "environment" in secret
        ):
            raise ProbeFailure("A Compose secret source is malformed.")
        actual_source = Path(str(secret["file"])).resolve()
        expected_source = (secret_directory / _SECRET_FILES[name]).resolve()
        if actual_source != expected_source:
            raise ProbeFailure("A Compose secret resolves outside the supplied secret directory.")
    return len(_ALL_SECRET_NAMES) + 1


def validate_secret_files(secret_directory: Path) -> int:
    if secret_directory.is_symlink() or not secret_directory.is_dir():
        raise ProbeFailure("The supplied secret directory is not a real directory.")
    directory_status = secret_directory.stat()
    linux_mode_checks = os.name != "nt"
    if linux_mode_checks and stat.S_IMODE(directory_status.st_mode) != 0o700:
        raise ProbeFailure("The Linux secret directory mode is not 0700.")
    for name in sorted(_ALL_SECRET_NAMES):
        path = secret_directory / _SECRET_FILES[name]
        if path.is_symlink():
            raise ProbeFailure("A production secret is not a regular nonsymlink file.")
        if not path.exists():
            if name in _REQUIRED_SECRET_NAMES:
                raise ProbeFailure("A required production secret file is missing.")
            continue
        if not path.is_file():
            raise ProbeFailure("A production secret is not a regular nonsymlink file.")
        file_status = path.stat()
        if linux_mode_checks and (
            stat.S_IMODE(file_status.st_mode) != 0o440
            or file_status.st_uid != directory_status.st_uid
            or file_status.st_gid != directory_status.st_gid
        ):
            raise ProbeFailure("A Linux secret has an unsafe mode, owner, or group.")
    return len(_ALL_SECRET_NAMES) + (2 if linux_mode_checks else 1)


def validate_secret_reader_group(configuration: dict[str, Any], secret_directory: Path) -> int:
    services = configuration.get("services")
    if not isinstance(services, dict):
        raise ProbeFailure("The Compose service catalog is malformed.")
    reader_groups: set[str] = set()
    secret_services: set[str] = set()
    for service_name, service in services.items():
        if not isinstance(service, dict):
            raise ProbeFailure("A Compose service entry is malformed.")
        if not _references(service.get("secrets")):
            continue
        secret_services.add(str(service_name))
        group_add = service.get("group_add") or []
        if not isinstance(group_add, list) or len(group_add) != 1:
            raise ProbeFailure("A secret-bearing service lacks the dedicated reader group.")
        reader_groups.add(str(group_add[0]))
    if secret_services != _SECRET_BEARING_SERVICES or len(reader_groups) != 1:
        raise ProbeFailure("The secret-bearing service and reader-group boundary is invalid.")
    reader_group = reader_groups.pop()
    if not reader_group.isdecimal() or reader_group == "0":
        raise ProbeFailure("The secret-reader group is not a non-root numeric GID.")
    if os.name != "nt" and int(reader_group) != secret_directory.stat().st_gid:
        raise ProbeFailure("The Compose secret-reader GID does not own the Linux secret files.")
    return len(_SECRET_BEARING_SERVICES) + 2


def _container_id(prefix: list[str], service: str) -> str:
    identifier = _run([*prefix, "ps", "-q", service]).strip()
    if not identifier or "\n" in identifier:
        raise ProbeFailure("A production runtime container could not be identified uniquely.")
    return identifier


def _inspect(identifier: str) -> dict[str, Any]:
    document = json.loads(_run(["docker", "inspect", identifier]))
    if not isinstance(document, list) or len(document) != 1 or not isinstance(document[0], dict):
        raise ProbeFailure("A production runtime inspection response is malformed.")
    return document[0]


def _environment_names(configuration: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for item in configuration.get("Env") or []:
        if not isinstance(item, str) or "=" not in item:
            raise ProbeFailure("A container environment entry is malformed.")
        names.add(item.partition("=")[0])
    return names


def validate_runtime_inspection(
    web: dict[str, Any],
    database: dict[str, Any],
    ingress: dict[str, Any],
    security_log: dict[str, Any],
) -> int:
    web_config = web.get("Config") or {}
    host_config = web.get("HostConfig") or {}
    ingress_config = ingress.get("Config") or {}
    ingress_host_config = ingress.get("HostConfig") or {}
    security_log_config = security_log.get("Config") or {}
    security_log_host_config = security_log.get("HostConfig") or {}
    if any(
        container.get("State", {}).get("Running") is not True
        for container in (web, database, ingress, security_log)
    ):
        raise ProbeFailure("A production runtime container is not running.")
    if web_config.get("User") != "10001:10001":
        raise ProbeFailure("The production web process is not pinned to numeric UID/GID 10001.")
    if (
        host_config.get("ReadonlyRootfs") is not True
        or host_config.get("PidsLimit") != 128
        or "ALL" not in (host_config.get("CapDrop") or [])
        or "no-new-privileges:true" not in (host_config.get("SecurityOpt") or [])
    ):
        raise ProbeFailure("The running web container lost a hardening control.")
    if host_config.get("PortBindings"):
        raise ProbeFailure("The running application container publishes a host port.")
    port_bindings = ingress_host_config.get("PortBindings") or {}
    if set(port_bindings) != {"8000/tcp"} or port_bindings["8000/tcp"] != [
        {"HostIp": "127.0.0.1", "HostPort": "8000"}
    ]:
        raise ProbeFailure("The running relay port binding is not loopback-only.")
    database_bindings = (database.get("HostConfig") or {}).get("PortBindings") or {}
    if database_bindings:
        raise ProbeFailure("The running database container publishes a host port.")
    if (
        ingress_config.get("User") != "101:101"
        or ingress_host_config.get("ReadonlyRootfs") is not True
        or ingress_host_config.get("PidsLimit") != 64
        or "ALL" not in (ingress_host_config.get("CapDrop") or [])
        or "no-new-privileges:true" not in (ingress_host_config.get("SecurityOpt") or [])
    ):
        raise ProbeFailure("The running loopback relay lost a hardening control.")
    if (
        security_log_config.get("User") != "10003:10003"
        or security_log_host_config.get("ReadonlyRootfs") is not True
        or security_log_host_config.get("PidsLimit") != 32
        or security_log_host_config.get("NetworkMode") != "none"
        or security_log_host_config.get("PortBindings")
        or "ALL" not in (security_log_host_config.get("CapDrop") or [])
        or "no-new-privileges:true" not in (security_log_host_config.get("SecurityOpt") or [])
    ):
        raise ProbeFailure("The security-log collector lost an isolation control.")

    expected_destinations = {f"/run/secrets/{name}" for name in _EXPECTED_SECRETS}
    secret_mounts = {
        mount.get("Destination")
        for mount in web.get("Mounts") or []
        if str(mount.get("Destination", "")).startswith("/run/secrets/")
    }
    if secret_mounts != expected_destinations:
        raise ProbeFailure("The running web container has an unexpected secret mount set.")
    if any(
        mount.get("RW") is not False
        for mount in web.get("Mounts") or []
        if mount.get("Destination") in expected_destinations
    ):
        raise ProbeFailure("A production web secret mount is writable.")
    environment_names = _environment_names(web_config)
    if not _FORBIDDEN_ENVIRONMENT_NAMES.isdisjoint(environment_names):
        raise ProbeFailure("A reusable secret is present in the web environment.")
    if environment_names.intersection(
        {
            "POSTGRES_ADMIN_USER",
            "POSTGRES_MIGRATION_USER",
            "POSTGRES_BACKUP_USER",
            "POSTGRES_AUDIT_USER",
        }
    ):
        raise ProbeFailure("The web environment exposes a privileged database identity.")
    ingress_secret_mounts = [
        mount
        for mount in ingress.get("Mounts") or []
        if str(mount.get("Destination", "")).startswith("/run/secrets/")
    ]
    ingress_environment = _environment_names(ingress_config)
    if ingress_secret_mounts or not _FORBIDDEN_ENVIRONMENT_NAMES.isdisjoint(ingress_environment):
        raise ProbeFailure("The loopback relay can access a reusable application secret.")
    nginx_mounts = [
        mount
        for mount in ingress.get("Mounts") or []
        if mount.get("Destination") == "/etc/nginx/nginx.conf"
    ]
    if len(nginx_mounts) != 1 or nginx_mounts[0].get("RW") is not False:
        raise ProbeFailure("The loopback relay configuration is not a single read-only mount.")
    socket_mounts = [
        mount
        for mount in web.get("Mounts") or []
        if mount.get("Destination") == "/run/security-log"
    ]
    if len(socket_mounts) != 1 or socket_mounts[0].get("RW") is not False:
        raise ProbeFailure("The web security-log socket mount is not read-only.")
    archive_destinations = {
        mount.get("Destination"): mount.get("RW") for mount in security_log.get("Mounts") or []
    }
    if archive_destinations != {
        "/run/security-log": True,
        "/var/lib/security-log": True,
    } or any(
        mount.get("Destination") == "/var/lib/security-log" for mount in web.get("Mounts") or []
    ):
        raise ProbeFailure("The separate security-log archive mount boundary is invalid.")
    security_log_secret_mounts = [
        mount
        for mount in security_log.get("Mounts") or []
        if str(mount.get("Destination", "")).startswith("/run/secrets/")
    ]
    if security_log_secret_mounts or not _FORBIDDEN_ENVIRONMENT_NAMES.isdisjoint(
        _environment_names(security_log_config)
    ):
        raise ProbeFailure("The security-log collector can access a reusable secret.")
    return 24


def _request(path: str, hostname: str, extra_headers: dict[str, str]) -> tuple[int, Any, bytes]:
    request = urllib.request.Request(
        f"http://127.0.0.1:8000{path}",
        headers={"Host": hostname, **extra_headers},
    )
    try:
        response = urllib.request.build_opener(_RejectRedirects()).open(request, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    except (OSError, urllib.error.URLError) as error:
        raise ProbeFailure("The production header probe could not reach loopback.") from error
    try:
        body = response.read(_MAXIMUM_RESPONSE_SIZE + 1)
        if len(body) > _MAXIMUM_RESPONSE_SIZE:
            raise ProbeFailure("A production header response was unexpectedly large.")
        return response.status, response.headers, body
    finally:
        response.close()


def _wait_for_web(hostname: str) -> None:
    for _ in range(30):
        try:
            status, _, _ = _request("/health/live/", hostname, {"X-Forwarded-Proto": "https"})
        except ProbeFailure:
            status = 0
        if status == 200:
            return
        time.sleep(1)
    raise ProbeFailure("The disposable production web service did not become ready.")


def _raw_http_exchange(payload: bytes) -> tuple[bytes, bool]:
    if not payload or len(payload) > _MAXIMUM_RAW_REQUEST_SIZE:
        raise ProbeFailure("An HTTP framing probe payload has an invalid size.")
    try:
        with socket.create_connection(("127.0.0.1", 8000), timeout=3) as connection:
            connection.settimeout(3)
            connection.sendall(payload)
            response = bytearray()
            peer_closed = False
            while len(response) <= _MAXIMUM_RESPONSE_SIZE:
                try:
                    chunk = connection.recv(65536)
                except TimeoutError:
                    break
                if not chunk:
                    peer_closed = True
                    break
                response.extend(chunk)
    except OSError as error:
        raise ProbeFailure("The raw HTTP framing probe could not reach loopback.") from error
    if len(response) > _MAXIMUM_RESPONSE_SIZE:
        raise ProbeFailure("A raw HTTP framing response was unexpectedly large.")
    return bytes(response), peer_closed


def _raw_request(
    hostname: str,
    *,
    request_line: str,
    headers: tuple[str, ...],
    body: bytes = b"",
) -> bytes:
    try:
        head = "\r\n".join((request_line, f"Host: {hostname}", *headers, "", "")).encode("ascii")
    except UnicodeEncodeError as error:
        raise ProbeFailure("The HTTP framing hostname is not ASCII.") from error
    return head + body


def _require_raw_status(payload: bytes, *, expected: int, probe: str) -> bytes:
    response, peer_closed = _raw_http_exchange(payload)
    statuses = [int(match) for match in _HTTP_STATUS_LINE.findall(response)]
    if statuses != [expected]:
        raise ProbeFailure(
            f"The {probe} framing control produced statuses={statuses!r}, "
            f"peer_closed={peer_closed!r}."
        )
    return response


def _require_framing_rejection(payload: bytes, *, probe: str) -> None:
    response, peer_closed = _raw_http_exchange(payload)
    statuses = [int(match) for match in _HTTP_STATUS_LINE.findall(response)]
    if len(statuses) != 1 or statuses[0] not in {400, 501} or not peer_closed:
        raise ProbeFailure(
            f"The {probe} framing ambiguity produced statuses={statuses!r}, "
            f"peer_closed={peer_closed!r}."
        )


def validate_request_framing(hostname: str) -> int:
    normal_get = _raw_request(
        hostname,
        request_line="GET /health/live/ HTTP/1.1",
        headers=("X-Forwarded-Proto: https", "Connection: close"),
    )
    get_response = _require_raw_status(normal_get, expected=200, probe="bodyless GET")
    if b'{"status": "ok"}' not in get_response:
        raise ProbeFailure("The bodyless GET framing control did not reach Django.")

    normal_content_length = _raw_request(
        hostname,
        request_line="GET /health/live/ HTTP/1.1",
        headers=(
            "X-Forwarded-Proto: https",
            "Content-Length: 0",
            "Connection: close",
        ),
    )
    _require_raw_status(normal_content_length, expected=200, probe="Content-Length")

    normal_chunked = _raw_request(
        hostname,
        request_line="GET /health/live/ HTTP/1.1",
        headers=(
            "X-Forwarded-Proto: https",
            "Transfer-Encoding: chunked",
            "Connection: close",
        ),
        body=b"0\r\n\r\n",
    )
    _require_raw_status(normal_chunked, expected=200, probe="chunked transfer")

    canary = _raw_request(
        hostname,
        request_line="GET /framing-canary HTTP/1.1",
        headers=("X-Forwarded-Proto: https", "Connection: close"),
    )
    ambiguous_requests = {
        "Transfer-Encoding plus Content-Length": _raw_request(
            hostname,
            request_line="GET /health/live/ HTTP/1.1",
            headers=(
                "X-Forwarded-Proto: https",
                "Transfer-Encoding: chunked",
                "Content-Length: 4",
                "Connection: keep-alive",
            ),
            body=b"0\r\n\r\n" + canary,
        ),
        "Content-Length plus Transfer-Encoding": _raw_request(
            hostname,
            request_line="GET /health/live/ HTTP/1.1",
            headers=(
                "X-Forwarded-Proto: https",
                "Content-Length: 5",
                "Transfer-Encoding: chunked",
                "Connection: keep-alive",
            ),
            body=b"0\r\n\r\n" + canary,
        ),
        "conflicting Content-Length": _raw_request(
            hostname,
            request_line="GET /health/live/ HTTP/1.1",
            headers=(
                "X-Forwarded-Proto: https",
                "Content-Length: 0",
                "Content-Length: 5",
                "Connection: keep-alive",
            ),
            body=canary,
        ),
        "multiple transfer codings": _raw_request(
            hostname,
            request_line="GET /health/live/ HTTP/1.1",
            headers=(
                "X-Forwarded-Proto: https",
                "Transfer-Encoding: chunked, identity",
                "Connection: keep-alive",
            ),
            body=b"0\r\n\r\n" + canary,
        ),
        "whitespace before header colon": _raw_request(
            hostname,
            request_line="GET /health/live/ HTTP/1.1",
            headers=(
                "X-Forwarded-Proto: https",
                "Transfer-Encoding : chunked",
                "Connection: keep-alive",
            ),
            body=b"0\r\n\r\n" + canary,
        ),
        "obsolete folded transfer header": _raw_request(
            hostname,
            request_line="GET /health/live/ HTTP/1.1",
            headers=(
                "X-Forwarded-Proto: https",
                "Transfer-Encoding:\r\n chunked",
                "Connection: keep-alive",
            ),
            body=b"0\r\n\r\n" + canary,
        ),
    }
    for probe, payload in ambiguous_requests.items():
        _require_framing_rejection(payload, probe=probe)
    return 9


def validate_http_boundary(hostname: str, secret_values: tuple[str, ...]) -> tuple[int, int]:
    _wait_for_web(hostname)
    status, headers, body = _request("/health/live/", hostname, {})
    if status not in (301, 302) or headers.get("Location") != f"https://{hostname}/health/live/":
        raise ProbeFailure("Plain HTTP did not redirect to the exact private HTTPS hostname.")
    if body:
        raise ProbeFailure("The plain-HTTP redirect unexpectedly returned application content.")

    status, headers, body = _request("/health/live/", hostname, {"X-Forwarded-Proto": "https"})
    if status != 200 or json.loads(body) != {"status": "ok"}:
        raise ProbeFailure("The trusted HTTPS proxy signal did not reach the safe health endpoint.")
    if headers.get("Strict-Transport-Security") != ("max-age=31536000; includeSubDomains; preload"):
        raise ProbeFailure("The production HSTS policy is incomplete.")

    for ambiguous in ("https,http", "HTTPS", "https http"):
        status, headers, _ = _request("/health/live/", hostname, {"X-Forwarded-Proto": ambiguous})
        if status not in (301, 302) or headers.get("Location") != (
            f"https://{hostname}/health/live/"
        ):
            raise ProbeFailure("An ambiguous forwarded scheme bypassed the canonical redirect.")

    status, headers, body = _request(
        "/health/live/",
        hostname,
        {
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "attacker.invalid",
            "X-Forwarded-Port": "444",
            "Forwarded": "host=attacker.invalid;proto=http",
        },
    )
    serialized = json.dumps(dict(headers)).encode() + body
    if status != 200 or b"attacker.invalid" in serialized:
        raise ProbeFailure("An untrusted forwarded host affected the production response.")

    status, _, body = _request("/health/live/", "attacker.invalid", {"X-Forwarded-Proto": "https"})
    if status != 400 or b"attacker.invalid" in body or b"Traceback" in body:
        raise ProbeFailure("An alternate Host header did not fail with a safe response.")

    status, headers, body = _request(
        "/definitely-not-a-route", hostname, {"X-Forwarded-Proto": "https"}
    )
    if status != 404 or b"Page not found" not in body or b"Traceback" in body:
        raise ProbeFailure("The production not-found response exposed unsafe diagnostics.")
    if any(value.encode() in body for value in secret_values):
        raise ProbeFailure("A production error response exposed a reusable secret.")
    if headers.get("X-Content-Type-Options") != "nosniff":
        raise ProbeFailure("A production error response lost its security headers.")
    return 5, 8


def _socket_reachable(port: int) -> bool:
    try:
        connection = socket.create_connection(("127.0.0.1", port), timeout=1)
    except OSError:
        return False
    connection.close()
    return True


def validate_runtime_behavior(
    web_id: str, ingress_id: str, security_log_id: str
) -> tuple[int, int]:
    uid = _run(["docker", "exec", web_id, "id", "-u"]).strip()
    gid = _run(["docker", "exec", web_id, "id", "-g"]).strip()
    if (uid, gid) != ("10001", "10001"):
        raise ProbeFailure("The running web process has an unexpected numeric identity.")
    process_status = _run(["docker", "exec", web_id, "cat", "/proc/1/status"])
    status_fields = dict(line.split(":", 1) for line in process_status.splitlines() if ":" in line)
    if status_fields.get("CapEff", "").strip() != "0000000000000000":
        raise ProbeFailure("The running web process retained an effective Linux capability.")
    if status_fields.get("NoNewPrivs", "").strip() != "1":
        raise ProbeFailure("The running web process can acquire new privileges.")
    _run_expect_failure(
        [
            "docker",
            "exec",
            web_id,
            "sh",
            "-c",
            "touch /app/.network-boundary-probe 2>/dev/null",
        ]
    )
    security_log_uid = _run(["docker", "exec", security_log_id, "id", "-u"]).strip()
    security_log_gid = _run(["docker", "exec", security_log_id, "id", "-g"]).strip()
    if (security_log_uid, security_log_gid) != ("10003", "10003"):
        raise ProbeFailure("The security-log collector has an unexpected numeric identity.")
    security_log_status = _run(["docker", "exec", security_log_id, "cat", "/proc/1/status"])
    security_log_fields = dict(
        line.split(":", 1) for line in security_log_status.splitlines() if ":" in line
    )
    if security_log_fields.get("CapEff", "").strip() != "0000000000000000":
        raise ProbeFailure("The security-log collector retained an effective Linux capability.")
    if security_log_fields.get("NoNewPrivs", "").strip() != "1":
        raise ProbeFailure("The security-log collector can acquire new privileges.")
    _run(["docker", "exec", security_log_id, "sh", "-c", "test ! -e /run/secrets"])
    _run_expect_failure(
        ["docker", "exec", security_log_id, "sh", "-c", "touch /security-log-root-probe"]
    )
    _run_expect_failure(["docker", "exec", web_id, "sh", "-c", "touch /run/security-log/bypass"])
    _run(["docker", "exec", web_id, "sh", "-c", "test ! -e /var/lib/security-log"])
    _run(
        [
            "docker",
            "exec",
            web_id,
            "python",
            "manage.py",
            "shell",
            "-c",
            (
                "import logging; logging.getLogger('security').warning("
                "'Security archive probe.', extra={'event':'security.archive.probe'})"
            ),
        ]
    )
    _run(
        [
            "docker",
            "exec",
            security_log_id,
            "python",
            "-c",
            (
                "import json,time; from pathlib import Path; "
                "events=Path('/var/lib/security-log/security-events.jsonl'); "
                "alerts=Path('/var/lib/security-log/security-alerts.jsonl'); found=False; "
                "found=any((time.sleep(.1) is None) and events.exists() and alerts.exists() and "
                "any(json.loads(line).get('event')=='security.archive.probe' "
                "for line in events.read_text().splitlines()) for _ in range(20)); "
                "raise SystemExit(0 if found else 1)"
            ),
        ]
    )
    archive_modes = _run(
        [
            "docker",
            "exec",
            security_log_id,
            "python",
            "-c",
            (
                "import os,stat; from pathlib import Path; "
                "paths=(Path('/run/security-log'),Path('/run/security-log/security.sock'),"
                "Path('/var/lib/security-log'),"
                "Path('/var/lib/security-log/security-events.jsonl')); "
                "print(','.join(oct(stat.S_IMODE(path.stat().st_mode)) for path in paths))"
            ),
        ]
    ).strip()
    if archive_modes != "0o711,0o622,0o700,0o600":
        raise ProbeFailure("The security-log socket or archive modes are unsafe.")
    ingress_uid = _run(["docker", "exec", ingress_id, "id", "-u"]).strip()
    ingress_gid = _run(["docker", "exec", ingress_id, "id", "-g"]).strip()
    if (ingress_uid, ingress_gid) != ("101", "101"):
        raise ProbeFailure("The loopback relay has an unexpected numeric identity.")
    ingress_status = _run(["docker", "exec", ingress_id, "cat", "/proc/1/status"])
    ingress_fields = dict(line.split(":", 1) for line in ingress_status.splitlines() if ":" in line)
    if ingress_fields.get("CapEff", "").strip() != "0000000000000000":
        raise ProbeFailure("The loopback relay retained an effective Linux capability.")
    if ingress_fields.get("NoNewPrivs", "").strip() != "1":
        raise ProbeFailure("The loopback relay can acquire new privileges.")
    _run_expect_failure(["docker", "exec", ingress_id, "sh", "-c", "touch /network-boundary-probe"])
    _run(["docker", "exec", ingress_id, "sh", "-c", "test ! -e /run/secrets"])
    _run(["docker", "exec", ingress_id, "nc", "-z", "-w", "2", "web", "8000"])
    validate_relay_destination(_run(["docker", "exec", ingress_id, "cat", "/etc/nginx/nginx.conf"]))
    _run(
        [
            "docker",
            "exec",
            web_id,
            "sh",
            "-c",
            'probe=/tmp/network-boundary-probe; touch "$probe"; rm -f "$probe"',
        ]
    )
    mounted_names = set(_run(["docker", "exec", web_id, "ls", "-1", "/run/secrets"]).splitlines())
    if mounted_names != _EXPECTED_SECRETS:
        raise ProbeFailure("The web process can see an unexpected secret filename.")
    database_role = (
        _run(
            [
                "docker",
                "exec",
                web_id,
                "python",
                "manage.py",
                "shell",
                "-c",
                (
                    "from django.db import connection; "
                    "cursor=connection.cursor(); cursor.execute('SELECT current_user'); "
                    "print(cursor.fetchone()[0])"
                ),
            ]
        )
        .strip()
        .splitlines()[-1]
    )
    if database_role != "budget_runtime":
        raise ProbeFailure("The web process is not using the runtime database role.")
    _run(
        [
            "docker",
            "exec",
            web_id,
            "python",
            "-c",
            "import socket; s=socket.create_connection(('db',5432),2); s.close()",
        ]
    )
    _run_expect_failure(
        [
            "docker",
            "exec",
            web_id,
            "python",
            "-c",
            "import socket; socket.create_connection(('1.1.1.1',443),2)",
        ]
    )
    if not _socket_reachable(8000) or any(_socket_reachable(port) for port in (5432, 2375, 2376)):
        raise ProbeFailure("The disposable host port boundary does not match the allowlist.")
    return 8, 25


def validate_no_secret_leakage(
    prefix: list[str],
    containers: tuple[dict[str, Any], ...],
    secret_directory: Path,
) -> int:
    values: list[str] = []
    for name in sorted(_ALL_SECRET_NAMES):
        path = secret_directory / _SECRET_FILES[name]
        if not path.exists():
            continue
        try:
            value = path.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError) as error:
            raise ProbeFailure("A disposable production secret could not be inspected.") from error
        if len(value) < 32:
            raise ProbeFailure("A disposable production secret is unexpectedly short.")
        values.append(value)
    images = {str((container.get("Config") or {}).get("Image", "")) for container in containers}
    if "" in images:
        raise ProbeFailure("The production web image could not be identified.")
    artifacts = "\n".join(
        [json.dumps(container, sort_keys=True) for container in containers]
        + [
            _run(["docker", "history", "--no-trunc", "--format", "{{.CreatedBy}}", image])
            for image in sorted(images)
        ]
        + [_run([*prefix, "logs", "--no-color", "ingress", "security-log", "web", "db"])]
    )
    if any(value in artifacts for value in values):
        raise ProbeFailure("A reusable secret appeared in runtime metadata, history, or logs.")
    lower_artifacts = artifacts.casefold()
    if any(marker in lower_artifacts for marker in ("authorization: bearer ", "password=")):
        raise ProbeFailure("A credential-shaped value appeared in runtime diagnostics.")
    return 5


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compose-file", type=Path, required=True)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--secret-directory", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    arguments = parse_arguments()
    stage = "input validation"
    try:
        compose_file = arguments.compose_file.resolve(strict=True)
        secret_directory = arguments.secret_directory.resolve(strict=True)
        prefix = _compose_prefix(compose_file, arguments.project_name)
        stage = "Compose model validation"
        configuration = json.loads(
            _run(
                [
                    *prefix,
                    "--profile",
                    "maintenance",
                    "--profile",
                    "recovery",
                    "config",
                    "--format",
                    "json",
                ]
            )
        )
        compose_checks = validate_compose_boundary(configuration)
        compose_checks += validate_secret_sources(configuration, secret_directory)
        compose_checks += validate_secret_files(secret_directory)
        compose_checks += validate_secret_reader_group(configuration, secret_directory)
        stage = "runtime metadata validation"
        web_id = _container_id(prefix, "web")
        database_id = _container_id(prefix, "db")
        ingress_id = _container_id(prefix, "ingress")
        security_log_id = _container_id(prefix, "security-log")
        web = _inspect(web_id)
        database = _inspect(database_id)
        ingress = _inspect(ingress_id)
        security_log = _inspect(security_log_id)
        inspection_checks = validate_runtime_inspection(web, database, ingress, security_log)
        stage = "temporary secret loading"
        secret_values = tuple(
            (secret_directory / _SECRET_FILES[name]).read_text(encoding="ascii").strip()
            for name in sorted(_ALL_SECRET_NAMES)
            if (secret_directory / _SECRET_FILES[name]).exists()
        )
        stage = "HTTP boundary validation"
        net03_checks, net05_checks = validate_http_boundary(arguments.hostname, secret_values)
        stage = "HTTP request-framing validation"
        framing_checks = validate_request_framing(arguments.hostname)
        stage = "runtime process validation"
        net04_checks, behavior_checks = validate_runtime_behavior(
            web_id, ingress_id, security_log_id
        )
        stage = "secret non-leakage validation"
        leakage_checks = validate_no_secret_leakage(
            prefix, (web, database, ingress, security_log), secret_directory
        )
    except ProbeFailure as error:
        print(
            f"Disposable production-boundary probe failed safely during {stage}: {error}",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
    except (OSError, UnicodeError, ValueError):
        print(
            f"Disposable production-boundary probe failed safely during {stage}.", file=sys.stderr
        )
        raise SystemExit(1) from None

    print(f"NET-03 pre-deployment controls passed ({net03_checks} HTTPS-policy checks).")
    print(f"NET-04 pre-deployment controls passed ({net04_checks} isolation checks).")
    print(f"NET-05 pre-deployment controls passed ({net05_checks} header/error checks).")
    print(f"HTTP-FRAMING controls passed ({framing_checks} request-boundary checks).")
    print(
        "NET-06 pre-deployment controls passed "
        f"({compose_checks + inspection_checks + behavior_checks + leakage_checks} runtime checks)."
    )
    print("NET-01 and NET-02 remain release-only device-boundary procedures.")
    print("Disposable production-boundary probe completed without sensitive-data output.")


if __name__ == "__main__":
    main()
