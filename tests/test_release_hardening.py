from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_release_evidence_inventory_is_complete_and_validated() -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/check_release_evidence.py"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "structurally complete" in completed.stdout

    evidence = json.loads((PROJECT_ROOT / "docs/release-evidence.json").read_text(encoding="utf-8"))
    assert {item["id"] for item in evidence["asvs"]["chapters"]} == {
        f"V{number}" for number in range(1, 18)
    }
    assert {item["id"] for item in evidence["security_tests"]} == set(range(1, 25))
    assert {item["id"] for item in evidence["release_gates"]} == set(range(1, 13))
    assert not any(
        item["status"] == "verified"
        for collection in (
            evidence["asvs"]["chapters"],
            evidence["security_tests"],
            evidence["release_gates"],
        )
        for item in collection
    )


def test_raw_security_reports_are_ignored_and_documented_as_sensitive() -> None:
    gitignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")
    runbook = (PROJECT_ROOT / "docs/RELEASE_HARDENING.md").read_text(encoding="utf-8")

    assert "security-reports/" in gitignore
    assert "Do not commit raw ZAP sessions" in runbook
    assert "real household data" in runbook
