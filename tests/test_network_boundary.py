import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _load_script(name: str, relative_path: str) -> ModuleType:
    specification = importlib.util.spec_from_file_location(name, PROJECT_ROOT / relative_path)
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


PRODUCTION_PROBE = _load_script(
    "production_boundary_probe", "deploy/network/run-production-boundary.py"
)
VM_PROBE = _load_script("private_ingress_probe", "deploy/network/verify-private-ingress.py")


@pytest.mark.parametrize(
    ("artifact", "expected"),
    (
        ('"POSTGRES_PASSWORD="', False),  # pragma: allowlist secret
        ('"POSTGRES_PASSWORD=[REDACTED]"', False),  # pragma: allowlist secret
        ("Authorization: Bearer [REDACTED]", False),  # pragma: allowlist secret
        ('"POSTGRES_PASSWORD=SCRAM-SHA-256"', False),  # pragma: allowlist secret
        ('"POSTGRES_PASSWORD=authentication"', False),  # pragma: allowlist secret
        ('"POSTGRES_PASSWORD=exposed-value-1234"', True),  # pragma: allowlist secret
        ("Authorization: Bearer exposed-token-1234", True),  # pragma: allowlist secret
    ),
)
def test_credential_shaped_runtime_values_distinguish_tokens_from_configuration(
    artifact: str, expected: bool
) -> None:
    assert PRODUCTION_PROBE._contains_credential_shaped_value(artifact) is expected


def _valid_compose_configuration() -> dict[str, Any]:
    services = {
        name: ({"network_mode": "none"} if not networks else {"networks": dict.fromkeys(networks)})
        for name, networks in PRODUCTION_PROBE._EXPECTED_SERVICE_NETWORKS.items()
    }
    services.update(
        {
            "db": {
                "networks": {"backend": None},
                "entrypoint": ["/bin/sh", "/usr/local/bin/start-postgres-tls.sh"],
                "environment": {"POSTGRES_HOST_AUTH_METHOD": "trust"},
                "secrets": [
                    {"source": "postgres_client_ca_certificate"},
                    {"source": "postgres_server_certificate"},
                    {"source": "postgres_server_private_key"},
                ],
                "volumes": [
                    {
                        "target": "/usr/local/bin/start-postgres-tls.sh",
                        "read_only": True,
                    },
                    {"target": "/etc/postgresql/pg_hba.conf", "read_only": True},
                ],
                "tmpfs": ["/run/postgresql-tls:rw,noexec,nosuid,nodev,size=1m,mode=0700"],
            },
            "web": {
                "networks": {"frontend": None, "backend": None},
                "environment": {"DATABASE_HOST": "db", "DATABASE_PORT": "5432"},
                "secrets": [
                    {"source": "django_secret_key"},
                    {"source": "django_mfa_encryption_key"},
                    {"source": "gunicorn_client_ca_certificate"},
                    {"source": "gunicorn_server_certificate"},
                    {"source": "gunicorn_server_private_key"},
                    {"source": "postgres_ca_certificate"},
                    {"source": "postgres_web_client_certificate"},
                    {"source": "postgres_web_client_private_key"},
                ],
                "command": list(PRODUCTION_PROBE._EXPECTED_WEB_COMMAND),
                "user": "10001:10001",
                "read_only": True,
                "cap_drop": ["ALL"],
                "pids_limit": 128,
                "security_opt": ["no-new-privileges:true"],
            },
            "ingress": {
                "networks": {"ingress": None, "frontend": None},
                "ports": [
                    {
                        "host_ip": "127.0.0.1",
                        "published": "8000",
                        "target": 8000,
                        "protocol": "tcp",
                    }
                ],
                "user": "101:101",
                "read_only": True,
                "cap_drop": ["ALL"],
                "pids_limit": 64,
                "security_opt": ["no-new-privileges:true"],
                "secrets": [
                    {"source": name} for name in sorted(PRODUCTION_PROBE._EXPECTED_INGRESS_SECRETS)
                ],
            },
        }
    )
    for service_name in PRODUCTION_PROBE._DATABASE_TLS_CLIENTS:
        certificate, private_key = PRODUCTION_PROBE._CLIENT_SECRETS[service_name]
        service = services[service_name]
        service.setdefault("environment", {}).update(
            {
                "PGSSLMODE": "verify-full",
                "PGSSLROOTCERT": "/run/secrets/postgres_ca_certificate",
                "PGSSLCERT": f"/run/secrets/{certificate}",
                "PGSSLKEY": f"/run/secrets/{private_key}",
            }
        )
        secrets = service.setdefault("secrets", [])
        if {"source": "postgres_ca_certificate"} not in secrets:
            secrets.append({"source": "postgres_ca_certificate"})
        secrets.extend(({"source": certificate}, {"source": private_key}))
    services["db-bootstrap"]["environment"]["APP_ENVIRONMENT"] = "production"
    return {
        "networks": {
            "ingress": {},
            "frontend": {"internal": True},
            "backend": {"internal": True},
        },
        "services": services,
    }


def test_production_probe_accepts_only_loopback_internal_compose_boundary() -> None:
    configuration = _valid_compose_configuration()

    assert PRODUCTION_PROBE.validate_compose_boundary(configuration) == 34

    configuration["services"]["ingress"]["ports"][0]["host_ip"] = "0.0.0.0"
    with pytest.raises(PRODUCTION_PROBE.ProbeFailure):
        PRODUCTION_PROBE.validate_compose_boundary(configuration)


@pytest.mark.parametrize(
    "mutator",
    (
        lambda configuration: configuration["networks"]["ingress"].update({"internal": True}),
        lambda configuration: configuration["networks"]["ingress"].update({"external": True}),
        lambda configuration: configuration["services"].update(
            {"unexpected": {"networks": {"backend": None}}}
        ),
        lambda configuration: configuration["services"]["web"].update(
            {"networks": {"frontend": None}}
        ),
        lambda configuration: configuration["services"]["web"].update({"network_mode": "host"}),
        lambda configuration: configuration["services"]["web"].update(
            {"extra_hosts": ["outside:192.0.2.1"]}
        ),
        lambda configuration: configuration["services"]["web"].update({"cap_add": ["NET_ADMIN"]}),
        lambda configuration: configuration["services"]["restic-key-rotate"].update(
            {"network_mode": "bridge"}
        ),
        lambda configuration: configuration["services"]["web"]["environment"].update(
            {"DATABASE_HOST": "outside"}
        ),
        lambda configuration: configuration["services"]["db-bootstrap"]["environment"].update(
            {"APP_ENVIRONMENT": "pentest"}
        ),
    ),
)
def test_production_probe_rejects_egress_allowlist_bypasses(mutator: Any) -> None:
    configuration = _valid_compose_configuration()
    mutator(configuration)

    with pytest.raises(PRODUCTION_PROBE.ProbeFailure):
        PRODUCTION_PROBE.validate_compose_boundary(configuration)


def test_production_probe_accepts_only_the_static_internal_relay_destination() -> None:
    configuration = (PROJECT_ROOT / "deploy" / "network" / "nginx.conf").read_text(encoding="utf-8")

    assert PRODUCTION_PROBE.validate_relay_destination(configuration) == 27

    for replacement in (
        "proxy_pass http://db:5432;",
        "proxy_pass http://$upstream;",
        "proxy_pass https://example.com;",
        "proxy_pass https://web:8443;\n            grpc_pass grpc://example.com:443;",
        "proxy_pass https://web:8443;\n            include /tmp/alternate-upstream.conf;",
    ):
        with pytest.raises(PRODUCTION_PROBE.ProbeFailure, match="relay destination"):
            PRODUCTION_PROBE.validate_relay_destination(
                configuration.replace("proxy_pass https://web:8443;", replacement)
            )

    for current, replacement in (
        ("proxy_ssl_verify on;", "proxy_ssl_verify off;"),
        ("proxy_ssl_name web;", "proxy_ssl_name attacker.invalid;"),
        (
            "proxy_ssl_trusted_certificate /run/secrets/gunicorn_ca_certificate;",
            "proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;",
        ),
        (
            "proxy_ssl_certificate /run/secrets/nginx_client_certificate;",
            "",
        ),
    ):
        with pytest.raises(PRODUCTION_PROBE.ProbeFailure, match="mutual TLS"):
            PRODUCTION_PROBE.validate_relay_destination(configuration.replace(current, replacement))

    for current, replacement in (
        ("default http;", "default https;"),
        ("~^https$ https;", "https https;"),
        (
            "proxy_set_header X-Forwarded-Proto $upstream_forwarded_proto;",
            "proxy_set_header X-Forwarded-Proto $scheme;",
        ),
        (
            'proxy_set_header Forwarded "";',
            "proxy_set_header Forwarded $http_forwarded;",
        ),
        (
            'proxy_set_header X-Forwarded-For "";',
            "proxy_set_header X-Forwarded-For $http_x_forwarded_for;",
        ),
        (
            'proxy_set_header X-Forwarded-Host "";',
            "proxy_set_header X-Forwarded-Host $http_x_forwarded_host;",
        ),
        (
            'proxy_set_header X-Forwarded-Port "";',
            "proxy_set_header X-Forwarded-Port $http_x_forwarded_port;",
        ),
        (
            'proxy_set_header X-Real-IP "";',
            "proxy_set_header X-Real-IP $http_x_real_ip;",
        ),
    ):
        with pytest.raises(PRODUCTION_PROBE.ProbeFailure, match="intermediary-header boundary"):
            PRODUCTION_PROBE.validate_relay_destination(configuration.replace(current, replacement))

    with pytest.raises(PRODUCTION_PROBE.ProbeFailure, match="intermediary-header boundary"):
        PRODUCTION_PROBE.validate_relay_destination(
            configuration.replace(
                'proxy_set_header X-Real-IP "";',
                'proxy_set_header X-Real-IP "";\n'
                "            proxy_set_header X-User-ID $http_x_user_id;",
            )
        )

    for current, replacement, message in (
        ("autoindex off;", "autoindex on;", "directory listing"),
        ("autoindex off;", "autoindex off;\n    root /tmp;", "directory listing"),
        (
            "if ($request_method = TRACE) {",
            "if ($request_method = CONNECT) {",
            "HTTP TRACE",
        ),
        ("return 405;", "return 200;", "HTTP TRACE"),
    ):
        with pytest.raises(PRODUCTION_PROBE.ProbeFailure, match=message):
            PRODUCTION_PROBE.validate_relay_destination(configuration.replace(current, replacement))


def test_production_probe_rejects_trace_without_reflecting_request_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payloads: list[bytes] = []

    def exchange(payload: bytes) -> tuple[bytes, bool]:
        payloads.append(payload)
        return b"HTTP/1.1 405 Not Allowed\r\nConnection: close\r\n\r\n", True

    monkeypatch.setattr(PRODUCTION_PROBE, "_raw_http_exchange", exchange)
    monkeypatch.setattr(PRODUCTION_PROBE, "_wait_for_web", lambda _hostname: None)
    responses = iter(
        (
            (302, {"Location": "https://budget.example.ts.net/accounts/login/"}, b""),
            (
                200,
                {"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"},
                b'{"status": "ok"}',
            ),
            *((302, {"Location": "https://budget.example.ts.net/accounts/login/"}, b""),) * 3,
            (200, {}, b""),
            (400, {}, b""),
            (404, {"X-Content-Type-Options": "nosniff"}, b"Page not found"),
        )
    )
    monkeypatch.setattr(PRODUCTION_PROBE, "_request", lambda *_args, **_kwargs: next(responses))

    assert PRODUCTION_PROBE.validate_http_boundary("budget.example.ts.net", ()) == (7, 8)
    assert len(payloads) == 1
    assert payloads[0].startswith(b"TRACE /health/live/ HTTP/1.1\r\n")
    assert b"X-Trace-Canary: must-not-be-reflected\r\n" in payloads[0]


def test_production_probe_fails_when_trace_content_is_reflected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(PRODUCTION_PROBE, "_wait_for_web", lambda _hostname: None)
    monkeypatch.setattr(
        PRODUCTION_PROBE,
        "_raw_http_exchange",
        lambda _payload: (
            b"HTTP/1.1 405 Not Allowed\r\n\r\nX-Trace-Canary: must-not-be-reflected",
            True,
        ),
    )

    with pytest.raises(PRODUCTION_PROBE.ProbeFailure, match="reflected request content"):
        PRODUCTION_PROBE.validate_http_boundary("budget.example.ts.net", ())


def test_production_probe_rejects_insecure_nonbrowser_requests_without_redirecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probes: list[tuple[str, dict[str, str]]] = []

    def request(path: str, _hostname: str, headers: dict[str, str]):
        probes.append((path, headers))
        return 400, {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}, b""

    monkeypatch.setattr(PRODUCTION_PROBE, "_request", request)

    assert PRODUCTION_PROBE.validate_nonbrowser_transport_boundary(
        "budget.example.ts.net"
    ) == 4 + len(PRODUCTION_PROBE._BLOCKED_OPERATIONAL_PATHS)
    assert probes[0] == ("/health/live/", {})
    assert [headers.get("X-Forwarded-Proto") for _, headers in probes[1:4]] == list(
        PRODUCTION_PROBE._AMBIGUOUS_PROXY_SCHEMES
    )
    assert [path for path, _ in probes[4:]] == list(PRODUCTION_PROBE._BLOCKED_OPERATIONAL_PATHS)


@pytest.mark.parametrize(
    "response",
    (
        (
            301,
            {
                "Location": "https://budget.example.ts.net/health/live/",
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
            b"",
        ),
        (
            400,
            {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
            b"unexpected body",
        ),
        (
            400,
            {
                "Location": "https://budget.example.ts.net/health/live/",
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
            b"",
        ),
        (400, {"X-Content-Type-Options": "nosniff"}, b""),
        (400, {"Cache-Control": "no-store"}, b""),
    ),
)
def test_production_probe_rejects_unsafe_nonbrowser_transport_results(
    monkeypatch: pytest.MonkeyPatch,
    response: tuple[int, dict[str, str], bytes],
) -> None:
    monkeypatch.setattr(PRODUCTION_PROBE, "_request", lambda *_args, **_kwargs: response)

    with pytest.raises(PRODUCTION_PROBE.ProbeFailure, match="transparently redirected"):
        PRODUCTION_PROBE.validate_nonbrowser_transport_boundary("budget.example.ts.net")


def test_production_probe_blocks_operational_endpoints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_paths: list[str] = []

    def request(path: str, _hostname: str, _headers: dict[str, str]):
        requested_paths.append(path)
        return 404, {"X-Content-Type-Options": "nosniff"}, b""

    monkeypatch.setattr(PRODUCTION_PROBE, "_request", request)

    assert PRODUCTION_PROBE.validate_operational_endpoint_boundary(
        "budget.example.ts.net", ()
    ) == len(PRODUCTION_PROBE._BLOCKED_OPERATIONAL_PATHS)
    assert requested_paths == list(PRODUCTION_PROBE._BLOCKED_OPERATIONAL_PATHS)
    assert "/health/ready/" in requested_paths


@pytest.mark.parametrize(
    "response",
    (
        (200, {"X-Content-Type-Options": "nosniff"}, b""),
        (404, {"X-Content-Type-Options": "nosniff"}, b"unexpected body"),
        (404, {}, b""),
        (404, {"X-Content-Type-Options": "nosniff", "X-Leak": "runtime-secret"}, b""),
    ),
)
def test_production_probe_rejects_unsafe_operational_endpoint_results(
    monkeypatch: pytest.MonkeyPatch,
    response: tuple[int, dict[str, str], bytes],
) -> None:
    monkeypatch.setattr(PRODUCTION_PROBE, "_request", lambda *_args, **_kwargs: response)

    with pytest.raises(PRODUCTION_PROBE.ProbeFailure, match="documentation or monitoring"):
        PRODUCTION_PROBE.validate_operational_endpoint_boundary(
            "budget.example.ts.net", ("runtime-secret",)
        )


def test_production_probe_accepts_only_encrypted_postgres_tcp_authentication() -> None:
    configuration = (PROJECT_ROOT / "deploy" / "postgres" / "pg_hba.conf").read_text(
        encoding="utf-8"
    )

    assert PRODUCTION_PROBE.validate_postgres_hba(configuration) == 1

    for replacement in (
        "host all all all cert map=budget_service",
        "hostssl all all all trust",
        "hostnossl all all all cert map=budget_service",
    ):
        with pytest.raises(PRODUCTION_PROBE.ProbeFailure, match="transport policy"):
            PRODUCTION_PROBE.validate_postgres_hba(
                configuration.replace("hostssl all all all cert map=budget_service", replacement)
            )


def test_production_probe_uses_a_ca_validated_certificateless_mtls_negative_probe() -> None:
    source = (PROJECT_ROOT / "deploy/network/run-production-boundary.py").read_text(
        encoding="utf-8"
    )

    assert '"--cacert"' in source
    assert '"/run/secrets/gunicorn_ca_certificate"' in source
    assert '"https://web:8443/health/live/"' in source
    assert (
        "nginx_client_certificate"
        not in source[source.index('"--cacert"') : source.index('"--cacert"') + 700]
    )


def test_production_probe_ties_compose_sources_to_guarded_secret_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret_directory = tmp_path / "secrets"
    secret_directory.mkdir(mode=0o700)
    secret_configuration = {}
    for name in PRODUCTION_PROBE._ALL_SECRET_NAMES:
        path = secret_directory / PRODUCTION_PROBE._SECRET_FILES[name]
        path.write_text("x" * 64, encoding="ascii")
        path.chmod(0o440)
        secret_configuration[name] = {"file": str(path)}
    configuration = {"secrets": secret_configuration}

    def validate_test_files() -> int:
        if PRODUCTION_PROBE.os.name == "nt":
            return PRODUCTION_PROBE.validate_secret_files(secret_directory)
        with monkeypatch.context() as context:
            context.setattr(PRODUCTION_PROBE.os, "name", "nt")
            return PRODUCTION_PROBE.validate_secret_files(secret_directory)

    expected_source_checks = len(PRODUCTION_PROBE._ALL_SECRET_NAMES) + 1
    expected_file_checks = len(PRODUCTION_PROBE._ALL_SECRET_NAMES) + 1
    assert (
        PRODUCTION_PROBE.validate_secret_sources(configuration, secret_directory)
        == expected_source_checks
    )
    assert validate_test_files() == expected_file_checks

    for name in PRODUCTION_PROBE._ALL_SECRET_NAMES - PRODUCTION_PROBE._REQUIRED_SECRET_NAMES:
        optional_path = secret_directory / PRODUCTION_PROBE._SECRET_FILES[name]
        optional_path.chmod(0o600)
        optional_path.unlink()
    assert validate_test_files() == expected_file_checks

    required_name = next(iter(PRODUCTION_PROBE._REQUIRED_SECRET_NAMES))
    required_path = secret_directory / PRODUCTION_PROBE._SECRET_FILES[required_name]
    required_path.chmod(0o600)
    required_path.unlink()
    with pytest.raises(PRODUCTION_PROBE.ProbeFailure, match="required production secret"):
        validate_test_files()

    foreign_path = tmp_path / "foreign-secret"
    foreign_path.write_text("x" * 64, encoding="ascii")
    configuration["secrets"]["django_secret_key"]["file"] = str(foreign_path)
    with pytest.raises(PRODUCTION_PROBE.ProbeFailure):
        PRODUCTION_PROBE.validate_secret_sources(configuration, secret_directory)


def test_production_probe_allowlists_every_secret_bearing_service(tmp_path: Path) -> None:
    secret_directory = tmp_path / "secrets"
    secret_directory.mkdir()
    reader_group = str(secret_directory.stat().st_gid or 10002)
    configuration = {
        "services": {
            name: {"secrets": ["placeholder"], "group_add": [reader_group]}
            for name in PRODUCTION_PROBE._SECRET_BEARING_SERVICES
        }
    }

    assert (
        PRODUCTION_PROBE.validate_secret_reader_group(configuration, secret_directory)
        == len(PRODUCTION_PROBE._SECRET_BEARING_SERVICES) + 2
    )

    configuration["services"]["unexpected"] = {
        "secrets": ["placeholder"],
        "group_add": [reader_group],
    }
    with pytest.raises(PRODUCTION_PROBE.ProbeFailure, match="service and reader-group boundary"):
        PRODUCTION_PROBE.validate_secret_reader_group(configuration, secret_directory)


def test_production_probe_enforces_unambiguous_http_request_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = iter(
        (
            (b'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{"status": "ok"}', False),
            (b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", False),
            (b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", False),
            *((b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n", True),) * 6,
        )
    )
    payloads: list[bytes] = []

    def exchange(payload: bytes) -> tuple[bytes, bool]:
        payloads.append(payload)
        return next(responses)

    monkeypatch.setattr(PRODUCTION_PROBE, "_raw_http_exchange", exchange)

    assert PRODUCTION_PROBE.validate_request_framing("budget.example.ts.net") == 9
    assert len(payloads) == 9
    assert payloads[0].startswith(b"GET /health/live/ HTTP/1.1\r\n")
    assert b"Content-Length: 0\r\n" in payloads[1]
    assert payloads[2].endswith(b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n")
    assert all(payload.count(b"GET /framing-canary HTTP/1.1") == 1 for payload in payloads[3:])
    assert b"Transfer-Encoding: chunked\r\nContent-Length: 4\r\n" in payloads[3]
    assert b"Content-Length: 0\r\nContent-Length: 5\r\n" in payloads[5]
    assert b"Transfer-Encoding : chunked\r\n" in payloads[7]
    assert b"Transfer-Encoding:\r\n chunked\r\n" in payloads[8]


@pytest.mark.parametrize(
    "exchange_result",
    (
        (b"HTTP/1.1 200 OK\r\n\r\n", True),
        (b"HTTP/1.1 400 Bad Request\r\n\r\n", False),
        (
            b"HTTP/1.1 400 Bad Request\r\n\r\nHTTP/1.1 404 Not Found\r\n\r\n",
            True,
        ),
    ),
)
def test_production_probe_rejects_unsafe_ambiguous_request_results(
    monkeypatch: pytest.MonkeyPatch,
    exchange_result: tuple[bytes, bool],
) -> None:
    monkeypatch.setattr(
        PRODUCTION_PROBE,
        "_raw_http_exchange",
        lambda _payload: exchange_result,
    )

    with pytest.raises(PRODUCTION_PROBE.ProbeFailure, match=r"statuses=.*peer_closed"):
        PRODUCTION_PROBE._require_framing_rejection(b"ambiguous", probe="test")


def test_private_ingress_accepts_exact_tagged_https_only_configuration() -> None:
    hostname = "budget.example.ts.net"
    tailscale_status = {
        "BackendState": "Running",
        "Self": {
            "Online": True,
            "DNSName": f"{hostname}.",
            "Tags": ["tag:budget-server"],
        },
    }
    serve_status = {
        "TCP": {"443": {"HTTPS": True}},
        "Web": {f"{hostname}:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8000"}}}},
        "AllowFunnel": {f"{hostname}:443": False},
    }
    firewall_status = """Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)
443/tcp on tailscale0 ALLOW IN Anywhere
22/tcp on tailscale0 ALLOW IN Anywhere
"""
    listener_status = """LISTEN 0 4096 127.0.0.1:8000 0.0.0.0:*
LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*
"""

    assert VM_PROBE.validate_tailscale_status(tailscale_status, hostname) == 4
    assert VM_PROBE.validate_serve_status(serve_status, hostname) == 4
    assert VM_PROBE.validate_firewall(firewall_status) == 3
    assert VM_PROBE.validate_listeners(listener_status) == 5


@pytest.mark.parametrize(("negotiated", "accepted"), (("TLSv1.3", True), ("TLSv1.2", False)))
def test_private_ingress_requires_tls13_preference_for_modern_client(
    monkeypatch: pytest.MonkeyPatch, negotiated: str, accepted: bool
) -> None:
    class Context:
        minimum_version: Any = None
        maximum_version: Any = None

    context = Context()

    class Response:
        status = 200

        @staticmethod
        def read(_limit: int) -> bytes:
            return b'{"status": "ok"}'

        @staticmethod
        def getheader(_name: str) -> str:
            return VM_PROBE._HSTS_POLICY

    class Socket:
        @staticmethod
        def version() -> str:
            return negotiated

    class Connection:
        sock = Socket()

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            assert args == ("budget.example.ts.net", 443)
            assert kwargs["context"] is context

        @staticmethod
        def request(*args: Any, **kwargs: Any) -> None:
            pass

        @staticmethod
        def getresponse() -> Response:
            return Response()

        @staticmethod
        def close() -> None:
            pass

    monkeypatch.setattr(VM_PROBE.ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(VM_PROBE.http.client, "HTTPSConnection", Connection)

    if accepted:
        assert VM_PROBE.validate_https("budget.example.ts.net") == 4
    else:
        with pytest.raises(VM_PROBE.VerificationFailure, match=r"did not prefer TLS 1\.3"):
            VM_PROBE.validate_https("budget.example.ts.net")
    assert context.minimum_version == VM_PROBE.ssl.TLSVersion.TLSv1_2
    assert context.maximum_version == VM_PROBE.ssl.TLSVersion.TLSv1_3


def test_private_ingress_proves_forwarding_headers_cannot_be_spoofed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class Response:
        status = 200

        @staticmethod
        def read(_limit: int) -> bytes:
            return b'{"status": "ok"}'

        @staticmethod
        def getheader(_name: str) -> None:
            return None

        @staticmethod
        def getheaders() -> list[tuple[str, str]]:
            return [("Content-Type", "application/json")]

    class Connection:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            captured["connection"] = (args, kwargs)

        def request(self, method: str, path: str, *, headers: dict[str, str]) -> None:
            captured["request"] = (method, path, headers)

        @staticmethod
        def getresponse() -> Response:
            return Response()

        def close(self) -> None:
            captured["closed"] = True

    monkeypatch.setattr(VM_PROBE.http.client, "HTTPSConnection", Connection)

    assert VM_PROBE.validate_forwarded_header_boundary("budget.example.ts.net") == 6
    assert captured["request"] == (
        "GET",
        "/health/live/",
        {"Accept": "application/json", **VM_PROBE._SPOOFED_FORWARDING_HEADERS},
    )
    assert captured["closed"] is True


@pytest.mark.parametrize(
    ("status", "headers", "message"),
    (
        (400, [], "overrode"),
        (200, [("X-Forwarded-For", "198.51.100.77")], "reflected"),
    ),
)
def test_private_ingress_rejects_forwarding_header_override_or_reflection(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    headers: list[tuple[str, str]],
    message: str,
) -> None:
    class Response:
        def __init__(self) -> None:
            self.status = status

        @staticmethod
        def read(_limit: int) -> bytes:
            return b'{"status": "ok"}'

        @staticmethod
        def getheader(_name: str) -> None:
            return None

        @staticmethod
        def getheaders() -> list[tuple[str, str]]:
            return headers

    class Connection:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        @staticmethod
        def request(*_args: Any, **_kwargs: Any) -> None:
            pass

        @staticmethod
        def getresponse() -> Response:
            return Response()

        @staticmethod
        def close() -> None:
            pass

    monkeypatch.setattr(VM_PROBE.http.client, "HTTPSConnection", Connection)

    with pytest.raises(VM_PROBE.VerificationFailure, match=message):
        VM_PROBE.validate_forwarded_header_boundary("budget.example.ts.net")


@pytest.mark.parametrize(
    ("mutator", "validator"),
    (
        (
            lambda document: document.update({"AllowFunnel": {"budget.example.ts.net:443": True}}),
            "serve",
        ),
        (
            lambda document: document["Web"]["budget.example.ts.net:443"]["Handlers"]["/"].update(
                {"Proxy": "http://0.0.0.0:8000"}
            ),
            "serve",
        ),
    ),
)
def test_private_ingress_rejects_public_or_nonloopback_proxy(mutator: Any, validator: str) -> None:
    hostname = "budget.example.ts.net"
    document = {
        "TCP": {"443": {"HTTPS": True}},
        "Web": {f"{hostname}:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8000"}}}},
    }
    mutator(document)

    assert validator == "serve"
    with pytest.raises(VM_PROBE.VerificationFailure):
        VM_PROBE.validate_serve_status(document, hostname)


@pytest.mark.parametrize(
    "firewall_status",
    (
        "Status: inactive",
        "Status: active\nDefault: allow (incoming), allow (outgoing)",
        ("Status: active\nDefault: deny (incoming), allow (outgoing)\n443/tcp ALLOW IN Anywhere"),
        (
            "Status: active\nDefault: deny (incoming), allow (outgoing)\n"
            "443/tcp on tailscale0 ALLOW IN Anywhere\n"
            "22/tcp on tailscale0 ALLOW IN Anywhere\n"
            "5432/tcp on tailscale0 ALLOW IN Anywhere"
        ),
    ),
)
def test_private_ingress_rejects_inactive_or_broad_firewall(firewall_status: str) -> None:
    with pytest.raises(VM_PROBE.VerificationFailure):
        VM_PROBE.validate_firewall(firewall_status)


@pytest.mark.parametrize(
    "listener_status",
    (
        "LISTEN 0 4096 0.0.0.0:8000 0.0.0.0:*",
        "LISTEN 0 4096 127.0.0.1:8000 0.0.0.0:*\nLISTEN 0 4096 0.0.0.0:5432 0.0.0.0:*",
        "not-enough-fields",
    ),
)
def test_private_ingress_rejects_public_or_administrative_listeners(
    listener_status: str,
) -> None:
    with pytest.raises(VM_PROBE.VerificationFailure):
        VM_PROBE.validate_listeners(listener_status)


def test_network_runners_are_bounded_and_keep_release_checks_honest() -> None:
    powershell_runner = (PROJECT_ROOT / "scripts/run-network-boundary.ps1").read_text(
        encoding="utf-8"
    )
    linux_runner = (PROJECT_ROOT / "scripts/run-network-boundary.sh").read_text(encoding="utf-8")
    vm_runner = (PROJECT_ROOT / "scripts/verify-private-ingress.sh").read_text(encoding="utf-8")
    policy = (PROJECT_ROOT / "deploy/network/tailnet-policy.example.hujson").read_text(
        encoding="utf-8"
    )
    runbook = (PROJECT_ROOT / "docs/PRIVATE_INGRESS.md").read_text(encoding="utf-8")
    framing_workflow = (PROJECT_ROOT / ".github/workflows/http-framing.yml").read_text(
        encoding="utf-8"
    )

    for runner in (powershell_runner, linux_runner):
        assert "budgetapp-network-boundary" in runner
        assert "down --volumes --remove-orphans" in runner
        assert "run-production-boundary.py" in runner
        assert "APP_ENVIRONMENT" in runner
        assert "BUDGET_SECRET_GID" in runner
    assert "BUDGET_BUILD_CONTEXT" in linux_runner
    assert 'git -C "$project_root" ls-files' in linux_runner
    assert "tailscale serve status --json" in vm_runner
    assert "ufw status verbose" in vm_runner
    assert "verify-private-ingress.py" in vm_runner
    assert '"ip": ["*"]' not in policy
    assert '"tag:budget-server:8000"' in policy
    assert "cannot satisfy" in runbook
    assert "NET-01" in runbook and "NET-02" in runbook
    assert "permissions:\n  contents: read" in framing_workflow
    assert "pull_request_target" not in framing_workflow
    assert "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0" in framing_workflow
    assert "sh scripts/run-network-boundary.sh" in framing_workflow
    assert "-exec sudo chown root:" in linux_runner
    assert "-exec sudo chmod 440" in linux_runner
