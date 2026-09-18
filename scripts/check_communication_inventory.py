"""Validate documented communication paths and the zero-egress application boundary."""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path
from typing import Any, NoReturn

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = PROJECT_ROOT / "docs" / "communication-inventory.json"
RUNTIME_ROOTS = (
    "audit",
    "budgets",
    "config",
    "core",
    "debts",
    "goals",
    "households",
    "identity",
    "imports",
    "ledger",
    "notifications",
    "periods",
    "reserves",
    "schedules",
    "spending",
)
RUNTIME_ENTRY_POINTS = ("manage.py",)
EXPECTED_FLOW_IDS = {
    "administrator_ssh",
    "backup_repository_mount",
    "checkpoint_repository_mount",
    "host_docker_control",
    "ingress_to_web",
    "private_browser_access",
    "security_log_archive",
    "services_to_postgresql",
    "tailscale_loopback_relay",
    "web_to_security_log",
}
EXPECTED_EXTERNAL_SERVICE_IDS = {
    "breached_password_corpus_source",
    "container_image_registries",
    "github_source_and_ci",
    "javascript_package_registry",
    "python_package_registry",
    "tailscale_private_network",
}
FLOW_FIELDS = {
    "data",
    "destination",
    "evidence",
    "id",
    "phase",
    "protection",
    "source",
    "transport",
    "user_supplied_destination",
}
EXTERNAL_SERVICE_FIELDS = {
    "destination",
    "evidence",
    "id",
    "phase",
    "purpose",
    "runtime_access",
    "user_supplied",
}
PROHIBITED_NETWORK_MODULES = {
    "aiohttp",
    "boto3",
    "ftplib",
    "http.client",
    "httpx",
    "imaplib",
    "paramiko",
    "poplib",
    "requests",
    "smtplib",
    "telnetlib",
    "urllib.request",
    "websocket",
    "websockets",
    "xmlrpc.client",
}
ALLOWED_UNIX_SOCKET_FILES = {"core/logging.py", "core/security_log_collector.py"}
EXPECTED_SERVICE_NETWORKS = {
    "backup": {"backend"},
    "db": {"backend"},
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


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _runtime_python_files(project_root: Path) -> list[Path]:
    files: list[Path] = []
    for root_name in RUNTIME_ROOTS:
        root = project_root / root_name
        if not root.is_dir():
            _fail(f"missing production runtime root {root_name!r}")
        files.extend(root.rglob("*.py"))
    for relative_path in RUNTIME_ENTRY_POINTS:
        path = project_root / relative_path
        if not path.is_file():
            _fail(f"missing production runtime entry point {relative_path!r}")
        files.append(path)
    return sorted(files)


def _validate_evidence(project_root: Path, evidence: Any, record_id: str) -> None:
    if not isinstance(evidence, list) or not evidence:
        _fail(f"communication record {record_id!r} has no evidence")
    for relative_path in evidence:
        if not isinstance(relative_path, str) or not relative_path:
            _fail(f"communication record {record_id!r} has malformed evidence")
        if not (project_root / relative_path).exists():
            _fail(f"communication record {record_id!r} references missing {relative_path!r}")


def _validate_records(
    project_root: Path,
    records: Any,
    expected_ids: set[str],
    expected_fields: set[str],
    user_supplied_field: str,
) -> None:
    if not isinstance(records, list):
        _fail("communication inventory records must be a list")
    identifiers: list[str] = []
    for record in records:
        if not isinstance(record, dict) or set(record) != expected_fields:
            _fail("communication inventory record fields differ from the schema")
        identifier = record.get("id")
        if not isinstance(identifier, str) or not identifier:
            _fail("communication inventory record has no identifier")
        identifiers.append(identifier)
        if record.get(user_supplied_field) is not False:
            _fail(f"communication record {identifier!r} unexpectedly accepts a user destination")
        for field, value in record.items():
            if field in {"evidence", user_supplied_field}:
                continue
            if not isinstance(value, str) or not value.strip():
                _fail(f"communication record {identifier!r} has an empty {field!r}")
        _validate_evidence(project_root, record["evidence"], identifier)
    if len(identifiers) != len(set(identifiers)) or set(identifiers) != expected_ids:
        _fail("communication inventory identifiers differ from the reviewed catalog")


def validate_inventory_document(project_root: Path, document: Any) -> tuple[int, int]:
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "last_reviewed",
        "user_supplied_external_destinations",
        "flows",
        "external_services",
    }:
        _fail("communication inventory top-level fields differ from the schema")
    if document["schema_version"] != 1 or document["last_reviewed"] != "2026-09-13":
        _fail("communication inventory version or review date is invalid")
    if document["user_supplied_external_destinations"] != []:
        _fail("the current release must not accept user-supplied external destinations")
    _validate_records(
        project_root,
        document["flows"],
        EXPECTED_FLOW_IDS,
        FLOW_FIELDS,
        "user_supplied_destination",
    )
    _validate_records(
        project_root,
        document["external_services"],
        EXPECTED_EXTERNAL_SERVICE_IDS,
        EXTERNAL_SERVICE_FIELDS,
        "user_supplied",
    )
    return len(document["flows"]), len(document["external_services"])


def _imported_network_module(node: ast.Import | ast.ImportFrom) -> str | None:
    if isinstance(node, ast.Import):
        for imported in node.names:
            if any(
                imported.name == module or imported.name.startswith(f"{module}.")
                for module in PROHIBITED_NETWORK_MODULES
            ):
                return imported.name
        return None
    module = node.module or ""
    if any(module == item or module.startswith(f"{item}.") for item in PROHIBITED_NETWORK_MODULES):
        return module
    imported_names = {imported.name for imported in node.names}
    if module == "urllib" and "request" in imported_names:
        return "urllib.request"
    if module == "http" and "client" in imported_names:
        return "http.client"
    return None


def validate_runtime_network_clients(project_root: Path = PROJECT_ROOT) -> tuple[int, int]:
    project_root = project_root.resolve()
    socket_files: set[str] = set()
    files = _runtime_python_files(project_root)
    for path in files:
        relative_path = path.relative_to(project_root).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative_path)
        imports_socket = False
        socket_attributes: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                if isinstance(node, ast.ImportFrom) and node.module == "socket":
                    _fail(f"direct socket symbol imports are prohibited in {relative_path}")
                if isinstance(node, ast.Import) and any(
                    item.name == "socket" and item.asname not in (None, "socket")
                    for item in node.names
                ):
                    _fail(f"socket module aliases are prohibited in {relative_path}")
                prohibited = _imported_network_module(node)
                if prohibited is not None:
                    _fail(
                        f"runtime network client {prohibited} is prohibited in "
                        f"{relative_path}:{node.lineno}"
                    )
                if (
                    isinstance(node, ast.Import)
                    and any(imported.name == "socket" for imported in node.names)
                ) or (isinstance(node, ast.ImportFrom) and node.module == "socket"):
                    imports_socket = True
            if isinstance(node, ast.Attribute):
                socket_attributes.add(node.attr)
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) > 1
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == "socket"
            ):
                if not isinstance(node.args[1], ast.Constant) or not isinstance(
                    node.args[1].value, str
                ):
                    _fail(f"dynamic socket member lookup is prohibited in {relative_path}")
                socket_attributes.add(node.args[1].value)
        if not imports_socket:
            continue
        if relative_path not in ALLOWED_UNIX_SOCKET_FILES:
            _fail(f"socket module is prohibited in runtime file {relative_path}")
        if not {"AF_UNIX", "SOCK_DGRAM"} <= socket_attributes or socket_attributes & {
            "AF_INET",
            "AF_INET6",
            "create_connection",
        }:
            _fail(f"runtime socket use is not Unix-datagram-only in {relative_path}")
        socket_files.add(relative_path)
    if project_root == PROJECT_ROOT.resolve() and socket_files != ALLOWED_UNIX_SOCKET_FILES:
        _fail("reviewed Unix socket inventory is stale")
    return len(files), len(socket_files)


def _literal_assignment(path: Path, name: str) -> Any:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        ):
            return ast.literal_eval(node.value)
    _fail(f"required deployment allowlist {name} is missing")


def _validate_deployment_boundaries(project_root: Path) -> None:
    compose = (project_root / "compose.yaml").read_text(encoding="utf-8")
    nginx = (project_root / "deploy/network/nginx.conf").read_text(encoding="utf-8")
    hardened = (project_root / "config/settings/hardened.py").read_text(encoding="utf-8")
    production = (project_root / "config/settings/production.py").read_text(encoding="utf-8")
    required_compose_fragments = {
        "DATABASE_HOST: db",
        'DATABASE_PORT: "5432"',
        '"127.0.0.1:8000:8000"',
        "network_mode: none",
    }
    if any(fragment not in compose for fragment in required_compose_fragments):
        _fail("production Compose communication destinations differ from the inventory")
    if "proxy_pass https://web:8443;" not in nginx:
        _fail("the ingress-to-web destination differs from the inventory")
    if 'EMAIL_BACKEND = "django.core.mail.backends.dummy.EmailBackend"' not in hardened:
        _fail("hardened settings do not disable the unused SMTP backend")
    if "if EXTERNAL_REDIRECT_ALLOWED_HOSTS:" not in production:
        _fail("production does not reject external redirect destinations")
    networks = _literal_assignment(
        project_root / "deploy/network/run-production-boundary.py",
        "_EXPECTED_SERVICE_NETWORKS",
    )
    if networks != EXPECTED_SERVICE_NETWORKS:
        _fail("production service network allowlist differs from the communication inventory")


def validate_communication_inventory(
    project_root: Path = PROJECT_ROOT,
) -> tuple[int, int, int, int]:
    project_root = project_root.resolve()
    document = json.loads((project_root / "docs/communication-inventory.json").read_text("utf-8"))
    flow_count, external_service_count = validate_inventory_document(project_root, document)
    runtime_file_count, socket_file_count = validate_runtime_network_clients(project_root)
    _validate_deployment_boundaries(project_root)
    return flow_count, external_service_count, runtime_file_count, socket_file_count


def main() -> int:
    try:
        flow_count, external_count, runtime_count, socket_count = validate_communication_inventory()
    except (OSError, SyntaxError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        print(f"Communication inventory validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "Communication inventory passed "
        f"({flow_count} flows, {external_count} external services, "
        f"{runtime_count} runtime Python files, {socket_count} Unix-socket files)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
