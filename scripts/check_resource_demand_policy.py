"""Validate documented resource-demand, concurrency, and response-time boundaries."""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path
from typing import Any, NoReturn

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = PROJECT_ROOT / "docs" / "resource-demand-policy.json"

EXPECTED_OPERATION_CONTEXTS = {
    "authentication-and-password-checks": "synchronous-http",
    "backup-restore-migration-rotation-and-audit": "operator-maintenance",
    "bounded-history-and-preview-pages": "synchronous-http",
    "csv-import-processing": "synchronous-http",
    "debt-and-schedule-projections": "synchronous-http",
    "notification-cleanup-and-security-logging": "scheduled-maintenance",
    "streaming-csv-exports": "streaming-http",
}
EXPECTED_TIMEOUTS = {
    "application-worker-silence": (30, "config/gunicorn.py"),
    "client-send-idle": (30, "deploy/network/nginx.conf"),
    "request-body-idle": (15, "deploy/network/nginx.conf"),
    "request-header-idle": (15, "deploy/network/nginx.conf"),
    "upstream-read-idle": (65, "deploy/network/nginx.conf"),
}
EXPECTED_DEPLOYMENT_LIMITS = {
    "web_workers": 2,
    "web_pids": 128,
    "ingress_worker_connections": 256,
    "ingress_pids": 64,
    "security_log_pids": 32,
}
EXPECTED_REQUIRED_CHECKS = {
    "scripts/check_input_validation_policy.py",
    "tests/test_authentication.py",
    "tests/test_csv_exports.py",
    "tests/test_csv_imports.py",
    "tests/test_debt_projections.py",
    "tests/test_deployment_config.py",
    "tests/test_network_boundary.py",
    "tests/test_security_log_archive.py",
}
EXPECTED_SOURCE_ASSERTIONS = {
    "audit-page-contract": (
        "audit/views.py",
        (
            "paginator = Paginator(events, 50)",
            "events.iterator(chunk_size=200)",
            "StreamingHttpResponse(",
        ),
    ),
    "csv-parser-contract": (
        "imports/services/parsing.py",
        (
            "upload.chunks(chunk_size=64 * 1024)",
            "if len(payload) > maximum_bytes:",
            "if len(rows) > maximum_rows:",
        ),
    ),
    "csv-upload-contract": (
        "config/settings/base.py",
        (
            "CSV_IMPORT_MAX_BYTES = 5 * 1024 * 1024",
            "CSV_IMPORT_MAX_ROWS = 10_000",
            "CSV_IMPORT_MAX_COLUMNS = 50",
            "CSV_IMPORT_MAX_CELL_LENGTH = 1_000",
        ),
    ),
    "debt-projection-contract": (
        "debts/services/projections.py",
        (
            "_MAX_DEBTS = 100",
            "_MAX_MONTHS = 1_200",
            "if len(debts) > _MAX_DEBTS:",
        ),
    ),
    "gunicorn-timeout-contract": (
        "config/gunicorn.py",
        ("timeout = 30", "graceful_timeout = 30"),
    ),
    "import-page-contract": (
        "imports/views.py",
        (")[:100]", '"rows_truncated":'),
    ),
    "ingress-timeout-contract": (
        "deploy/network/nginx.conf",
        (
            "client_header_timeout 15s;",
            "client_body_timeout 15s;",
            "proxy_read_timeout 65s;",
            "send_timeout 30s;",
            "client_max_body_size 6m;",
        ),
    ),
    "notification-page-contract": ("notifications/views.py", (")[:200]",)),
    "recurrence-contract": (
        "schedules/recurrence.py",
        ("_MAX_WINDOW_DAYS = 366 * 25", "_MAX_OCCURRENCES = 10_000"),
    ),
    "schedule-sync-contract": (
        "schedules/services/sync.py",
        (
            "_MAX_SYNC_DAYS = 366 * 5",
            "if (window_end - window_start).days > _MAX_SYNC_DAYS:",
        ),
    ),
    "security-log-size-contract": (
        "core/logging.py",
        (
            "MAX_SECURITY_LOG_DATAGRAM_BYTES = 32 * 1024",
            "len(payload) > MAX_SECURITY_LOG_DATAGRAM_BYTES",
        ),
    ),
    "transaction-page-contract": (
        "spending/views.py",
        (
            "paginator = Paginator(entries, 50)",
            "entries.iterator(chunk_size=200)",
            "StreamingHttpResponse(",
        ),
    ),
}
EXPECTED_RESIDUAL_RISKS = {
    "Maximum-size CSV commit and worst-case projection timing still need representative "
    "release-host measurements.",
    "A long-running streamed export can occupy one of the two synchronous web workers.",
    "Production Compose does not yet enforce CPU or memory quotas for every service.",
}


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(f"{label} must be non-empty text")
    return value


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        _fail(f"{label} must be a non-empty string list")
    values = [_text(item, label) for item in value]
    if len(values) != len(set(values)):
        _fail(f"{label} contains duplicates")
    return values


def _safe_path(relative_path: str, *, project_root: Path = PROJECT_ROOT) -> Path:
    if Path(relative_path).is_absolute():
        _fail(f"resource-demand evidence must be relative: {relative_path}")
    path = (project_root / relative_path).resolve()
    try:
        path.relative_to(project_root.resolve())
    except ValueError:
        _fail(f"resource-demand evidence escapes project root: {relative_path}")
    if not path.exists():
        _fail(f"missing resource-demand evidence: {relative_path}")
    return path


def validate_source_contract(
    assertion_id: str,
    source: str,
    *,
    expected: dict[str, tuple[str, tuple[str, ...]]] = EXPECTED_SOURCE_ASSERTIONS,
) -> None:
    try:
        _, fragments = expected[assertion_id]
    except KeyError:
        _fail(f"unknown source assertion: {assertion_id}")
    missing = [fragment for fragment in fragments if fragment not in source]
    if missing:
        _fail(f"resource-demand source contract changed for {assertion_id}: {missing}")


def _validate_operations(policy: dict[str, Any], project_root: Path) -> None:
    operations = policy.get("operations")
    if not isinstance(operations, list) or any(not isinstance(item, dict) for item in operations):
        _fail("operations must contain objects")
    operation_fields = {
        "id",
        "execution_context",
        "demand",
        "bounds",
        "response_strategy",
        "failure_and_retry",
        "evidence",
    }
    discovered: dict[str, str] = {}
    for operation in operations:
        if set(operation) != operation_fields:
            _fail("resource-demand operation fields changed")
        operation_id = _text(operation["id"], "operation id")
        if operation_id in discovered:
            _fail(f"duplicate resource-demand operation: {operation_id}")
        discovered[operation_id] = _text(
            operation["execution_context"], f"{operation_id} execution context"
        )
        _text(operation["demand"], f"{operation_id} demand")
        _string_list(operation["bounds"], f"{operation_id} bounds")
        _text(operation["response_strategy"], f"{operation_id} response strategy")
        _text(operation["failure_and_retry"], f"{operation_id} failure and retry")
        for evidence in _string_list(operation["evidence"], f"{operation_id} evidence"):
            _safe_path(evidence, project_root=project_root)
    if discovered != EXPECTED_OPERATION_CONTEXTS:
        _fail("resource-demand operation inventory changed")


def _validate_timeouts(policy: dict[str, Any], project_root: Path) -> None:
    timeouts = policy.get("response_timeouts")
    if not isinstance(timeouts, list) or any(not isinstance(item, dict) for item in timeouts):
        _fail("response_timeouts must contain objects")
    discovered: dict[str, tuple[int, str]] = {}
    for timeout_record in timeouts:
        if set(timeout_record) != {"id", "seconds", "purpose", "evidence"}:
            _fail("response-timeout fields changed")
        timeout_id = _text(timeout_record["id"], "response timeout id")
        seconds = timeout_record["seconds"]
        if not isinstance(seconds, int) or isinstance(seconds, bool) or seconds < 1:
            _fail(f"invalid response timeout: {timeout_id}")
        evidence = _text(timeout_record["evidence"], f"{timeout_id} evidence")
        _safe_path(evidence, project_root=project_root)
        _text(timeout_record["purpose"], f"{timeout_id} purpose")
        if timeout_id in discovered:
            _fail(f"duplicate response timeout: {timeout_id}")
        discovered[timeout_id] = (seconds, evidence)
    if discovered != EXPECTED_TIMEOUTS:
        _fail("response-timeout inventory changed")
    if discovered["upstream-read-idle"][0] <= discovered["application-worker-silence"][0]:
        _fail("ingress timeout must outlast the application worker timeout")


def _validate_deployment_limits(policy: dict[str, Any], project_root: Path) -> None:
    if policy.get("deployment_limits") != EXPECTED_DEPLOYMENT_LIMITS:
        _fail("resource-demand deployment limits changed")
    compose = yaml.safe_load((project_root / "compose.yaml").read_text(encoding="utf-8"))
    services = compose["services"]
    web_command = services["web"]["command"]
    try:
        worker_count = int(web_command[web_command.index("--workers") + 1])
    except (AttributeError, IndexError, TypeError, ValueError):
        _fail("web worker configuration is invalid")
    actual = {
        "web_workers": worker_count,
        "web_pids": services["web"]["pids_limit"],
        "ingress_worker_connections": 256,
        "ingress_pids": services["ingress"]["pids_limit"],
        "security_log_pids": services["security-log"]["pids_limit"],
    }
    nginx_source = (project_root / "deploy/network/nginx.conf").read_text(encoding="utf-8")
    if "worker_connections 256;" not in nginx_source:
        _fail("ingress worker-connection limit changed")
    if actual != EXPECTED_DEPLOYMENT_LIMITS:
        _fail(f"runtime resource-demand deployment limits changed: {actual}")


def _validate_required_checks(policy: dict[str, Any], project_root: Path) -> None:
    required = set(_string_list(policy.get("required_checks"), "required checks"))
    if required != EXPECTED_REQUIRED_CHECKS:
        _fail("resource-demand required checks changed")
    for relative_path in required:
        _safe_path(relative_path, project_root=project_root)


def _validate_source_assertions(policy: dict[str, Any], project_root: Path) -> None:
    assertions = policy.get("source_assertions")
    if not isinstance(assertions, list) or any(not isinstance(item, dict) for item in assertions):
        _fail("source_assertions must contain objects")
    documented: dict[str, tuple[str, tuple[str, ...]]] = {}
    for assertion in assertions:
        if set(assertion) != {"id", "path", "contains"}:
            _fail("resource-demand source assertion fields changed")
        assertion_id = _text(assertion["id"], "source assertion id")
        path = _text(assertion["path"], f"{assertion_id} source path")
        fragments = tuple(_string_list(assertion["contains"], f"{assertion_id} fragments"))
        if assertion_id in documented:
            _fail(f"duplicate resource-demand source assertion: {assertion_id}")
        documented[assertion_id] = (path, fragments)
    if documented != EXPECTED_SOURCE_ASSERTIONS:
        _fail("resource-demand source assertion inventory changed")
    for assertion_id, (relative_path, _) in documented.items():
        source = _safe_path(relative_path, project_root=project_root).read_text(encoding="utf-8")
        validate_source_contract(assertion_id, source)


def _validate_gate_wiring(project_root: Path) -> None:
    powershell_gate = (project_root / "scripts/check.ps1").read_text(encoding="utf-8")
    shell_gate = (project_root / "scripts/check.sh").read_text(encoding="utf-8")
    if "scripts\\check_resource_demand_policy.py" not in powershell_gate:
        _fail("resource-demand checker is missing from the PowerShell gate")
    if "scripts/check_resource_demand_policy.py" not in shell_gate:
        _fail("resource-demand checker is missing from the shell gate")


def validate_resource_demand_policy(
    policy: dict[str, Any], *, project_root: Path = PROJECT_ROOT, today: date | None = None
) -> None:
    expected_fields = {
        "schema_version",
        "policy_id",
        "asvs_requirement",
        "last_reviewed",
        "next_review_due",
        "availability_objective",
        "operations",
        "response_timeouts",
        "deployment_limits",
        "required_checks",
        "source_assertions",
        "residual_risks",
        "summary",
    }
    if set(policy) != expected_fields:
        _fail("resource-demand policy fields changed")
    if (
        policy["schema_version"] != 1
        or policy["policy_id"] != "household-budget-resource-demand-v1"
    ):
        _fail("unsupported resource-demand policy identity")
    if policy["asvs_requirement"] != "v5.0.0-15.1.3":
        _fail("resource-demand ASVS requirement changed")
    _text(policy["availability_objective"], "availability objective")

    reviewed = date.fromisoformat(_text(policy["last_reviewed"], "last_reviewed"))
    due = date.fromisoformat(_text(policy["next_review_due"], "next_review_due"))
    if due <= reviewed or (due - reviewed).days > 90:
        _fail("resource-demand review cadence exceeds 90 days")
    if (today or date.today()) > due:
        _fail("resource-demand policy review is overdue")

    _validate_operations(policy, project_root)
    _validate_timeouts(policy, project_root)
    _validate_deployment_limits(policy, project_root)
    _validate_required_checks(policy, project_root)
    _validate_source_assertions(policy, project_root)
    _validate_gate_wiring(project_root)

    risks = set(_string_list(policy.get("residual_risks"), "residual risks"))
    if risks != EXPECTED_RESIDUAL_RISKS:
        _fail("resource-demand residual risks changed")
    expected_summary = {
        "operations": len(EXPECTED_OPERATION_CONTEXTS),
        "interactive_operations": sum(
            context.endswith("http") for context in EXPECTED_OPERATION_CONTEXTS.values()
        ),
        "response_timeouts": len(EXPECTED_TIMEOUTS),
        "source_assertions": len(EXPECTED_SOURCE_ASSERTIONS),
        "required_checks": len(EXPECTED_REQUIRED_CHECKS),
        "residual_risks": len(EXPECTED_RESIDUAL_RISKS),
    }
    if policy.get("summary") != expected_summary:
        _fail("resource-demand policy summary is stale")


def main() -> int:
    try:
        policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        if not isinstance(policy, dict):
            _fail("resource-demand policy must be a JSON object")
        validate_resource_demand_policy(policy)
    except (
        KeyError,
        OSError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
        yaml.YAMLError,
    ) as error:
        print(f"resource-demand policy check failed: {error}", file=sys.stderr)
        return 1
    print(
        "Resource-demand policy passed: "
        f"{len(EXPECTED_OPERATION_CONTEXTS)} operations, {len(EXPECTED_TIMEOUTS)} timeouts, "
        f"{len(EXPECTED_SOURCE_ASSERTIONS)} source contracts."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
