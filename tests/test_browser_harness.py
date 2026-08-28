from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (PROJECT_ROOT / path).read_text(encoding="utf-8")


def test_browser_image_and_dependencies_are_exactly_pinned() -> None:
    package = json.loads(_read("package.json"))
    lock = json.loads(_read("package-lock.json"))
    dockerfile = _read("Dockerfile.browser-tests")

    assert package["private"] is True
    assert package["devDependencies"] == {
        "@axe-core/playwright": "4.13.0",
        "@playwright/test": "1.62.1",
    }
    assert lock["packages"][""]["devDependencies"] == package["devDependencies"]
    assert lock["packages"]["node_modules/@playwright/test"]["version"] == "1.62.1"
    assert re.search(
        r"^FROM mcr\.microsoft\.com/playwright:v1\.62\.1-noble@sha256:[0-9a-f]{64}$",
        dockerfile,
        re.MULTILINE,
    )
    assert "npm ci --ignore-scripts" in dockerfile
    assert "npm audit --audit-level=high" in dockerfile
    assert "USER pwuser" in dockerfile


def test_browser_compose_service_is_disposable_and_synthetic_only() -> None:
    compose = yaml.safe_load(_read("compose.pentest.yaml"))
    service = compose["services"]["browser-tests"]

    assert service["profiles"] == ["browser"]
    assert service["environment"] == {"PLAYWRIGHT_BASE_URL": "http://pentest-web:8000"}
    assert service["depends_on"]["pentest-web"]["condition"] == "service_healthy"
    assert service["networks"] == ["pentest_frontend"]
    assert service["volumes"] == ["browser_credentials:/run/browser-credentials:ro"]
    assert "ports" not in service
    assert service["read_only"] is True
    assert service["user"] == "pwuser"
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["shm_size"] == "1gb"
    assert any("/tmp:" in mount and "uid=1001" in mount for mount in service["tmpfs"])
    assert all(network["internal"] is True for network in compose["networks"].values())
    credentials = compose["services"]["browser-credentials-init"]
    assert credentials["network_mode"] == "none"
    assert credentials["read_only"] is True
    assert credentials["cap_drop"] == ["ALL"]
    assert set(credentials["cap_add"]) == {"CHOWN", "DAC_READ_SEARCH"}
    assert "browser_credentials:/run/browser-credentials" in credentials["volumes"]


def test_browser_runner_uses_fixed_project_and_always_removes_volumes() -> None:
    powershell = _read("scripts/run-browser-tests.ps1")
    shell = _read("scripts/run-browser-tests.sh")

    for runner in (powershell, shell):
        assert "budgetapp-browser" in runner
        assert "--profile" in runner and "browser" in runner
        assert "down" in runner
        assert "--volumes" in runner
        assert "--remove-orphans" in runner
        assert "build browser-tests" in runner
        assert "up" in runner and "--build" in runner and "--wait" in runner
        assert "run" in runner and "--rm" in runner and "--no-deps" in runner
        assert "browser-tests" in runner
        assert "browser-credentials-init" in runner
        assert "pentest-auth-sessions" not in runner
    assert "finally" in powershell
    assert "trap cleanup" in shell


def test_playwright_matrix_is_bounded_and_keeps_artifacts_ephemeral() -> None:
    config = _read("playwright.config.mjs")
    expected_projects = {
        "auth-setup",
        "chromium-desktop",
        "firefox-desktop",
        "webkit-desktop",
        "chromium-phone",
        "firefox-narrow",
        "webkit-iphone",
        "webkit-ipad",
        "session-lifecycle",
    }

    assert 'const expectedBaseUrl = "http://pentest-web:8000"' in config
    assert "baseURL !== expectedBaseUrl" in config
    assert set(re.findall(r'name: "([a-z-]+)"', config)) == expected_projects
    assert "workers: 1" in config
    assert "retries: 0" in config
    assert 'outputDir: "/tmp/playwright-results"' in config
    for artifact in ("trace", "screenshot", "video"):
        assert f'{artifact}: "off"' in config


def test_browser_specs_cover_real_mfa_security_accessibility_and_workflows() -> None:
    auth = _read("browser-tests/auth.setup.mjs")
    security = _read("browser-tests/security-accessibility.spec.mjs")
    workflows = _read("browser-tests/responsive-workflows.spec.mjs")
    support = _read("browser-tests/support.mjs")
    application_javascript = _read("core/static/core/app.js")

    credential_preparation = _read("deploy/pentest/prepare-browser-credentials.py")

    assert 'page.goto("/audit/")' in auth
    assert "getByLabel(/email/iu)" in auth
    assert "currentTotpCode" in auth
    assert "chmodSync(authenticationState, 0o400)" in auth
    assert "httpOnly" in auth and 'sameSite).toBe("Strict")' in auth
    assert "sessionCookie?.expires).toBe(-1)" in auth
    assert "content-security-policy" in security
    assert "unsafe-inline" in security and "unsafe-eval" in security
    assert "window.localStorage" in security and "window.sessionStorage" in security
    assert "window.__budgetInjected" in security
    assert "sessionCookie?.expires).toBe(-1)" in security
    assert "AxeBuilder" in security
    assert all(tag in security for tag in ("wcag2a", "wcag2aa", "wcag21a", "wcag21aa"))
    assert "expectNoHorizontalOverflow" in workflows
    assert "Switch color theme" in workflows
    assert "Skip to main content" in workflows
    assert "toBeFocused" in workflows
    assert "44 CSS pixels" in workflows
    assert "manual expense" in workflows
    assert "Remove category budget" in workflows
    assert "Reason" in workflows and "confirmation" in workflows
    lifecycle = _read("browser-tests/session-lifecycle.spec.mjs")
    assert "page.goBack()" in lifecycle
    assert "browser.newContext(" in lifecycle
    assert "household-budget-theme" in lifecycle
    assert "pentest_budget_sessionid" in lifecycle
    assert "Sign out" in lifecycle
    assert "createHmac" in support and 'readFileSync(path, "ascii")' in support
    assert set(re.findall(r'"(alex_[a-z]+)": Path', credential_preparation)) == {
        "alex_password",
        "alex_totp",
    }
    assert "riley" not in credential_preparation
    assert "os.fchown" in credential_preparation
    assert "os.chmod(DESTINATION, 0o500)" in credential_preparation
    assert "PWUSER_UID = 1001" in credential_preparation
    unsafe_sinks = r"\.innerHTML\s*=|\beval\s*\(|document\.write\s*\("
    assert not re.search(unsafe_sinks, application_javascript)


def test_browser_ci_is_read_only_pinned_and_not_a_privileged_event() -> None:
    workflow = _read(".github/workflows/browser.yml")
    dependabot = yaml.safe_load(_read(".github/dependabot.yml"))

    assert re.search(r"^  pull_request:$", workflow, re.MULTILINE)
    assert re.search(r"^  workflow_dispatch:$", workflow, re.MULTILINE)
    assert "pull_request_target" not in workflow
    assert re.search(r"^permissions:\n  contents: read$", workflow, re.MULTILINE)
    assert re.search(r"actions/checkout@[0-9a-f]{40}", workflow)
    assert "persist-credentials: false" in workflow
    assert "sh scripts/run-browser-tests.sh" in workflow
    npm_updates = [
        update for update in dependabot["updates"] if update["package-ecosystem"] == "npm"
    ]
    assert len(npm_updates) == 1
    assert npm_updates[0]["directory"] == "/"
