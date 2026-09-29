"""Validate source, dependency, container, secret, and finding scan coverage."""

from __future__ import annotations

import ast
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any, NoReturn

PROJECT_ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = PROJECT_ROOT / "docs" / "security-scan-boundary.json"

EXPECTED_CONTROL_IDS = {
    "exhaustive-scan-target-inventory",
    "locked-dependency-audits",
    "release-candidate-rerun-boundary",
    "repository-secret-scan",
    "source-static-analysis",
    "suppression-and-finding-disposition",
    "three-image-vulnerability-and-secret-gate",
}
EXPECTED_SCAN_TARGETS = {
    "bandit-application": {
        "scanner": "bandit",
        "scope": "application packages and deploy/pentest",
        "blocking_threshold": "any reported issue",
        "evidence": ["scripts/check.ps1", "scripts/check.sh"],
    },
    "bandit-operations": {
        "scanner": "bandit",
        "scope": "deploy, scripts, and manage.py",
        "blocking_threshold": "high severity",
        "evidence": ["scripts/check.ps1", "scripts/check.sh"],
    },
    "detect-secrets-source": {
        "scanner": "detect-secrets",
        "scope": "repository-owned files outside tool caches and design mockups",
        "blocking_threshold": "any non-allowlisted finding",
        "evidence": ["scripts/secret_scan.py"],
    },
    "pip-audit-python-lock": {
        "scanner": "pip-audit",
        "scope": "requirements-dev.lock including requirements-prod.lock",
        "blocking_threshold": "any advisory",
        "evidence": [
            ".github/workflows/quality.yml",
            "requirements-dev.lock",
            "requirements-prod.lock",
        ],
    },
    "npm-audit-browser-lock": {
        "scanner": "npm audit",
        "scope": "package-lock.json browser-test dependencies",
        "blocking_threshold": "high or critical advisory",
        "evidence": [
            "Dockerfile.browser-tests",
            "package-lock.json",
            ".github/workflows/browser.yml",
        ],
    },
    "trivy-application-image": {
        "scanner": "Trivy",
        "scope": "household-budget release image",
        "blocking_threshold": "high or critical vulnerability or embedded secret",
        "evidence": [".github/workflows/quality.yml", "Dockerfile"],
    },
    "trivy-ingress-image": {
        "scanner": "Trivy",
        "scope": "household-budget-ingress release image",
        "blocking_threshold": "high or critical vulnerability or embedded secret",
        "evidence": [".github/workflows/quality.yml", "deploy/network/Dockerfile"],
    },
    "trivy-backup-image": {
        "scanner": "Trivy",
        "scope": "household-budget-backup release image",
        "blocking_threshold": "high or critical vulnerability or embedded secret",
        "evidence": [".github/workflows/quality.yml", "deploy/backup/Dockerfile"],
    },
}
EXPECTED_SCANNER_FINDINGS = {
    "M10-F001": {"severity": "Critical", "state": "Retested"},
    "M10-F006": {"severity": "High", "state": "Retested"},
    "M10-F018": {"severity": "High", "state": "Retested"},
    "M10-F021": {"severity": "High", "state": "Retested"},
    "M10-F022": {"severity": "High", "state": "Retested"},
}
EXPECTED_SUPPRESSIONS = {
    "pentest-auth-directory-readonly-mode": {
        "path": "deploy/pentest/authenticate-sessions.py",
        "tool": "bandit",
        "rule": "B103",
        "reason": (
            "The disposable credential directory intentionally becomes read-and-execute-only "
            "after exclusive secret creation; the parent remains inside the guarded synthetic "
            "stack."
        ),
    }
}
EXPECTED_SECURITY_EVIDENCE = {
    ".github/workflows/quality.yml",
    "Dockerfile.browser-tests",
    "docs/SECURITY_FINDINGS.md",
    "docs/security-scan-boundary.json",
    "scripts/check_security_scan_boundary.py",
    "scripts/secret_scan.py",
    "tests/test_security_scan_boundary.py",
}
SOURCE_CONTRACTS = {
    ".github/workflows/quality.yml": (
        "pip_audit --requirement requirements-dev.lock",
        "--no-deps --disable-pip --strict",
        "aquasec/trivy:0.70.0@sha256:",
        "image --scanners vuln,secret --severity HIGH,CRITICAL --exit-code 1",
        "household-budget:${{ github.sha }}",
        "household-budget-ingress:${{ github.sha }}",
        "household-budget-backup:${{ github.sha }}",
        "name: release-image-sboms-${{ github.sha }}",
    ),
    "Dockerfile.browser-tests": (
        "COPY package.json package-lock.json ./",
        "RUN npm ci --ignore-scripts --no-audit --fund=false",
        "RUN npm audit --audit-level=high",
    ),
    "scripts/secret_scan.py": (
        '"scan",',
        '"--all-files",',
        "_is_approved_public_fingerprint",
        "_is_approved_hash_only_file",
        'print("Potential secrets detected:", file=sys.stderr)',
    ),
    "scripts/check.sh": (
        '"$python_path" -m bandit -q -c pyproject.toml -r',
        '"$python_path" -m bandit -q -lll -c pyproject.toml -r deploy scripts manage.py',
    ),
    "scripts/check.ps1": (
        "& $pythonPath -m bandit -q -c pyproject.toml -r @sourceDirectories",
        '$operationsSource = @("deploy", "scripts", "manage.py")',
        "& $pythonPath -m bandit -q -lll -c pyproject.toml -r @operationsSource",
    ),
}
SCANNER_MARKERS = ("Trivy", "pip-audit", "npm audit", "Bandit", "detect-secrets")
SOURCE_DIRECTORIES = (
    "audit",
    "budgets",
    "config",
    "core",
    "debts",
    "deploy",
    "goals",
    "households",
    "identity",
    "imports",
    "ledger",
    "notifications",
    "periods",
    "reserves",
    "schedules",
    "scripts",
    "spending",
)


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        _fail(f"{label} must be non-empty text")
    return value


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        _fail(f"{label} must be a non-empty list")
    values = [_text(item, f"{label} item") for item in value]
    if len(values) != len(set(values)):
        _fail(f"{label} contains duplicates")
    return values


def _safe_path(value: Any, *, project_root: Path, label: str) -> str:
    relative = _text(value, label).split("#", maxsplit=1)[0]
    path = Path(relative)
    if path.is_absolute():
        _fail(f"{label} must be repository relative")
    resolved = (project_root / path).resolve()
    try:
        resolved.relative_to(project_root.resolve())
    except ValueError:
        _fail(f"{label} escapes the repository")
    if not resolved.exists():
        _fail(f"{label} is missing: {relative}")
    return relative


def _test_functions(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    }


def _lock_packages(path: Path) -> set[tuple[str, str]]:
    packages: set[tuple[str, str]] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.partition(";")[0].strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^\s]+)", line)
        if match is None:
            _fail(f"dependency lock contains a non-exact entry: {path.name}:{raw_line}")
        packages.add((re.sub(r"[-_.]+", "-", match.group(1)).casefold(), match.group(2)))
    if not packages:
        _fail(f"dependency lock is empty: {path.name}")
    return packages


def discover_scanner_findings(project_root: Path = PROJECT_ROOT) -> dict[str, dict[str, str]]:
    source = (project_root / "docs/SECURITY_FINDINGS.md").read_text(encoding="utf-8")
    headings = list(re.finditer(r"(?m)^## (M10-F\d{3}) — .+$", source))
    findings: dict[str, dict[str, str]] = {}
    for index, heading in enumerate(headings):
        end = headings[index + 1].start() if index + 1 < len(headings) else len(source)
        section = source[heading.start() : end]
        if not any(marker in section for marker in SCANNER_MARKERS):
            continue
        identifier = heading.group(1)
        severity_match = re.search(r"(?m)^- Severity: (.+)$", section)
        state_match = re.search(r"(?m)^- State: (.+)$", section)
        if severity_match is None or state_match is None:
            _fail(f"scanner finding lacks severity or state: {identifier}")
        findings[identifier] = {
            "severity": severity_match.group(1).strip(),
            "state": state_match.group(1).strip(),
        }
    return findings


def discover_bandit_suppressions(project_root: Path = PROJECT_ROOT) -> set[tuple[str, str]]:
    suppressions: set[tuple[str, str]] = set()
    paths = [project_root / "manage.py"]
    for directory in SOURCE_DIRECTORIES:
        paths.extend((project_root / directory).rglob("*.py"))
    for path in paths:
        source = path.read_text(encoding="utf-8")
        for match in re.finditer(r"#\s*nosec\s+([A-Z]\d{3}(?:\s*,\s*[A-Z]\d{3})*)", source):
            relative = path.relative_to(project_root).as_posix()
            suppressions.update((relative, rule.strip()) for rule in match.group(1).split(","))
    return suppressions


def validate_security_scan_boundary(
    inventory: dict[str, Any],
    *,
    project_root: Path = PROJECT_ROOT,
    today: date | None = None,
) -> None:
    if set(inventory) != {
        "controls",
        "inventory_id",
        "last_reviewed",
        "next_review_due",
        "release_boundary",
        "reviewed_suppressions",
        "scan_targets",
        "scanner_findings",
        "schema_version",
        "security_test_id",
        "summary",
    }:
        _fail("security-scan inventory fields changed")
    if inventory["schema_version"] != 1 or inventory["inventory_id"] != (
        "budgetapp-security-scan-boundary-v1"
    ):
        _fail("unsupported security-scan inventory identity")
    if inventory["security_test_id"] != 14:
        _fail("security-scan inventory must remain bound to security test 14")
    reviewed = date.fromisoformat(_text(inventory["last_reviewed"], "last_reviewed"))
    due = date.fromisoformat(_text(inventory["next_review_due"], "next_review_due"))
    if due <= reviewed or (due - reviewed).days > 90:
        _fail("security-scan review cadence exceeds 90 days")
    if (today or date.today()) > due:
        _fail("security-scan inventory review is overdue")

    controls = inventory.get("controls")
    if not isinstance(controls, list) or any(not isinstance(item, dict) for item in controls):
        _fail("security-scan controls must contain objects")
    observed: set[str] = set()
    test_cache: dict[str, set[str]] = {}
    for control in controls:
        if set(control) != {"evidence", "id", "objective", "repository_status", "test_refs"}:
            _fail("security-scan control fields changed")
        identifier = _text(control["id"], "control id")
        if identifier in observed:
            _fail(f"duplicate security-scan control: {identifier}")
        observed.add(identifier)
        _text(control["objective"], f"{identifier} objective")
        if control["repository_status"] != "implemented":
            _fail(f"security-scan control is not implemented: {identifier}")
        for evidence in _string_list(control["evidence"], f"{identifier} evidence"):
            _safe_path(evidence, project_root=project_root, label=f"{identifier} evidence")
        for reference in _string_list(control["test_refs"], f"{identifier} test_refs"):
            try:
                relative, function = reference.split("::", maxsplit=1)
            except ValueError:
                _fail(f"invalid security-scan test reference: {reference}")
            path = project_root / _safe_path(
                relative, project_root=project_root, label=f"{identifier} test"
            )
            functions = test_cache.setdefault(relative, _test_functions(path))
            if not relative.startswith("tests/") or function not in functions:
                _fail(f"security-scan test reference is missing: {reference}")
    if observed != EXPECTED_CONTROL_IDS:
        _fail("security-scan control inventory changed")

    targets = inventory.get("scan_targets")
    if not isinstance(targets, list) or any(not isinstance(item, dict) for item in targets):
        _fail("scan_targets must contain objects")
    documented_targets: dict[str, dict[str, Any]] = {}
    for target in targets:
        if set(target) != {"blocking_threshold", "evidence", "id", "scanner", "scope"}:
            _fail("scan target fields changed")
        identifier = _text(target["id"], "scan target id")
        if identifier in documented_targets:
            _fail(f"duplicate scan target: {identifier}")
        evidence = _string_list(target["evidence"], f"{identifier} evidence")
        for path in evidence:
            _safe_path(path, project_root=project_root, label=f"{identifier} evidence")
        documented_targets[identifier] = {
            "scanner": _text(target["scanner"], f"{identifier} scanner"),
            "scope": _text(target["scope"], f"{identifier} scope"),
            "blocking_threshold": _text(
                target["blocking_threshold"], f"{identifier} blocking threshold"
            ),
            "evidence": evidence,
        }
    if documented_targets != EXPECTED_SCAN_TARGETS:
        _fail("security scan target inventory changed")

    prod_packages = _lock_packages(project_root / "requirements-prod.lock")
    dev_packages = _lock_packages(project_root / "requirements-dev.lock")
    if not prod_packages < dev_packages:
        _fail("development dependency audit no longer strictly contains production dependencies")
    package_document = json.loads((project_root / "package-lock.json").read_text(encoding="utf-8"))
    if package_document.get("lockfileVersion") != 3:
        _fail("browser dependency lock must remain npm lockfile version 3")

    scanner_findings = inventory.get("scanner_findings")
    if not isinstance(scanner_findings, list) or any(
        not isinstance(item, dict) for item in scanner_findings
    ):
        _fail("scanner_findings must contain objects")
    documented_findings: dict[str, dict[str, str]] = {}
    for finding in scanner_findings:
        if set(finding) != {"id", "severity", "state"}:
            _fail("scanner finding fields changed")
        identifier = _text(finding["id"], "scanner finding id")
        if identifier in documented_findings:
            _fail(f"duplicate scanner finding: {identifier}")
        documented_findings[identifier] = {
            "severity": _text(finding["severity"], f"{identifier} severity"),
            "state": _text(finding["state"], f"{identifier} state"),
        }
    if documented_findings != EXPECTED_SCANNER_FINDINGS:
        _fail("scanner finding inventory changed")
    if discover_scanner_findings(project_root) != EXPECTED_SCANNER_FINDINGS:
        _fail("scanner finding disposition changed")
    if any(
        finding["severity"] in {"High", "Critical"} and finding["state"] != "Retested"
        for finding in documented_findings.values()
    ):
        _fail("high or critical scanner finding is not retested")

    suppressions = inventory.get("reviewed_suppressions")
    if not isinstance(suppressions, list) or any(
        not isinstance(item, dict) for item in suppressions
    ):
        _fail("reviewed_suppressions must contain objects")
    documented_suppressions: dict[str, dict[str, str]] = {}
    for suppression in suppressions:
        if set(suppression) != {"id", "path", "reason", "rule", "tool"}:
            _fail("reviewed suppression fields changed")
        identifier = _text(suppression["id"], "reviewed suppression id")
        if identifier in documented_suppressions:
            _fail(f"duplicate reviewed suppression: {identifier}")
        path = _safe_path(
            suppression["path"], project_root=project_root, label=f"{identifier} path"
        )
        documented_suppressions[identifier] = {
            "path": path,
            "tool": _text(suppression["tool"], f"{identifier} tool"),
            "rule": _text(suppression["rule"], f"{identifier} rule"),
            "reason": _text(suppression["reason"], f"{identifier} reason"),
        }
    if documented_suppressions != EXPECTED_SUPPRESSIONS:
        _fail("reviewed scanner suppression inventory changed")
    expected_suppression_pairs = {
        (record["path"], record["rule"]) for record in EXPECTED_SUPPRESSIONS.values()
    }
    if discover_bandit_suppressions(project_root) != expected_suppression_pairs:
        _fail("Bandit suppression inventory changed")

    workflow = (project_root / ".github/workflows/quality.yml").read_text(encoding="utf-8")
    browser_dockerfile = (project_root / "Dockerfile.browser-tests").read_text(encoding="utf-8")
    trivy_gate = "image --scanners vuln,secret --severity HIGH,CRITICAL --exit-code 1"
    if workflow.count(trivy_gate) != 3:
        _fail("each of the three release images must retain an independent blocking Trivy gate")
    forbidden = ("--ignore-vuln", "--ignore-unfixed", "--exit-code 0")
    if any(token in workflow or token in browser_dockerfile for token in forbidden):
        _fail("vulnerability scan contains a forbidden suppression")
    if list(project_root.glob(".trivyignore*")) or list(
        (project_root / ".github").rglob(".trivyignore*")
    ):
        _fail("Trivy ignore files are forbidden")

    release_boundary = inventory.get("release_boundary")
    if not isinstance(release_boundary, dict) or set(release_boundary) != {
        "evidence_location",
        "required_observation",
        "status",
    }:
        _fail("security-scan release boundary fields changed")
    if release_boundary["status"] != "pending":
        _fail("security-scan release boundary must remain pending")
    _text(release_boundary["required_observation"], "required release observation")
    _safe_path(
        release_boundary["evidence_location"],
        project_root=project_root,
        label="release evidence location",
    )
    if inventory.get("summary") != {
        "scan_targets": 8,
        "source_scans": 3,
        "dependency_scans": 2,
        "image_scans": 3,
        "scanner_findings": 5,
        "reviewed_suppressions": 1,
        "release_pending": 1,
    }:
        _fail("security-scan summary is stale")

    for relative, fragments in SOURCE_CONTRACTS.items():
        source = (project_root / relative).read_text(encoding="utf-8")
        missing = [fragment for fragment in fragments if fragment not in source]
        if missing:
            _fail(f"security-scan source contract changed in {relative}: {missing}")

    release_document = json.loads(
        (project_root / "docs/release-evidence.json").read_text(encoding="utf-8")
    )
    tests = release_document.get("security_tests")
    if not isinstance(tests, list):
        _fail("security tests are malformed")
    matching = [item for item in tests if isinstance(item, dict) and item.get("id") == 14]
    if len(matching) != 1:
        _fail("security test 14 is missing or duplicated")
    security_test = matching[0]
    if security_test.get("status") != "implemented" or not EXPECTED_SECURITY_EVIDENCE.issubset(
        set(security_test.get("evidence", []))
    ):
        _fail("security test 14 is not scan-boundary ready")
    if "last_verified" in security_test:
        _fail("security test 14 must remain unverified without release-candidate evidence")

    for gate_path, fragment in (
        ("scripts/check.ps1", "scripts\\check_security_scan_boundary.py"),
        ("scripts/check.sh", "scripts/check_security_scan_boundary.py"),
    ):
        if fragment not in (project_root / gate_path).read_text(encoding="utf-8"):
            _fail(f"security-scan checker is missing from {gate_path}")


def main() -> int:
    try:
        inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
        validate_security_scan_boundary(inventory)
    except (OSError, SyntaxError, json.JSONDecodeError, ValueError) as error:
        print(f"Security-scan validation failed: {error}", file=sys.stderr)
        return 1
    summary = inventory["summary"]
    print(
        "Security-scan inventory passed: "
        f"{summary['scan_targets']} targets, {summary['scanner_findings']} retested findings, "
        "release observation pending."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
