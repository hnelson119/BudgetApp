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


def _valid_compose_configuration() -> dict[str, Any]:
    return {
        "networks": {
            "ingress": {},
            "frontend": {"internal": True},
            "backend": {"internal": True},
        },
        "services": {
            "db": {"networks": {"backend": None}},
            "web": {
                "networks": {"frontend": None, "backend": None},
                "secrets": [
                    {"source": "django_secret_key"},
                    {"source": "django_mfa_encryption_key"},
                    {"source": "postgres_runtime_password"},
                ],
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
            },
        },
    }


def test_production_probe_accepts_only_loopback_internal_compose_boundary() -> None:
    configuration = _valid_compose_configuration()

    assert PRODUCTION_PROBE.validate_compose_boundary(configuration) == 15

    configuration["services"]["ingress"]["ports"][0]["host_ip"] = "0.0.0.0"
    with pytest.raises(PRODUCTION_PROBE.ProbeFailure):
        PRODUCTION_PROBE.validate_compose_boundary(configuration)


def test_production_probe_ties_compose_sources_to_guarded_secret_directory(
    tmp_path: Path,
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

    assert PRODUCTION_PROBE.validate_secret_sources(configuration, secret_directory) == 13
    assert PRODUCTION_PROBE.validate_secret_files(secret_directory) in {13, 14}

    for name in PRODUCTION_PROBE._ALL_SECRET_NAMES - PRODUCTION_PROBE._REQUIRED_SECRET_NAMES:
        optional_path = secret_directory / PRODUCTION_PROBE._SECRET_FILES[name]
        optional_path.chmod(0o600)
        optional_path.unlink()
    assert PRODUCTION_PROBE.validate_secret_files(secret_directory) in {13, 14}

    required_name = next(iter(PRODUCTION_PROBE._REQUIRED_SECRET_NAMES))
    required_path = secret_directory / PRODUCTION_PROBE._SECRET_FILES[required_name]
    required_path.chmod(0o600)
    required_path.unlink()
    with pytest.raises(PRODUCTION_PROBE.ProbeFailure, match="required production secret"):
        PRODUCTION_PROBE.validate_secret_files(secret_directory)

    foreign_path = tmp_path / "foreign-secret"
    foreign_path.write_text("x" * 64, encoding="ascii")
    configuration["secrets"]["django_secret_key"]["file"] = str(foreign_path)
    with pytest.raises(PRODUCTION_PROBE.ProbeFailure):
        PRODUCTION_PROBE.validate_secret_sources(configuration, secret_directory)


def test_production_probe_enforces_unambiguous_http_request_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = iter(
        (
            (b'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{"status": "ok"}', True),
            (b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", True),
            (b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n", True),
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

    with pytest.raises(PRODUCTION_PROBE.ProbeFailure, match="not rejected and closed"):
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
