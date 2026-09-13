from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_client_technologies import (
    BINARY_SUFFIXES,
    CLIENT_SURFACE_ROOTS,
    PROJECT_ROOT,
    TEXT_SUFFIXES,
    validate_client_technologies,
)


def _client_tree(tmp_path: Path) -> Path:
    for relative_root in CLIENT_SURFACE_ROOTS:
        root = tmp_path / relative_root
        root.mkdir(parents=True)
        (root / "safe.html").write_text("<!doctype html><p>Safe</p>", encoding="utf-8")
    return tmp_path


def test_client_technology_inventory_accepts_the_production_surface() -> None:
    files = validate_client_technologies()

    assert files
    assert {path.suffix.casefold() for path in files} <= TEXT_SUFFIXES | BINARY_SUFFIXES


def test_client_technology_inventory_runs_in_both_quality_gates() -> None:
    powershell_gate = (PROJECT_ROOT / "scripts/check.ps1").read_text(encoding="utf-8")
    shell_gate = (PROJECT_ROOT / "scripts/check.sh").read_text(encoding="utf-8")

    assert "scripts\\check_client_technologies.py" in powershell_gate
    assert "scripts/check_client_technologies.py" in shell_gate


@pytest.mark.parametrize(
    ("filename", "content", "message"),
    (
        ("legacy.swf", b"fixture", "legacy client artifact"),
        ("unknown.bin", b"fixture", "unreviewed production client artifact type"),
        ("plugin.html", b"<object data='legacy.swf'></object>", "plug-in element"),
        ("activex.js", b"const control = new ActiveXObject('legacy');", "ActiveX API"),
        ("plugin.js", b"navigator.plugins.length", "browser plug-in enumeration"),
        ("reference.css", b"url('legacy.xap')", "legacy client artifact reference"),
        ("prototype.js", b"payload.__proto__ = value", "prototype-related property"),
        ("constructor.js", b"payload.constructor", "prototype-related property"),
        ("merge.js", b"Object.assign(target, payload)", "object or reflection mutation API"),
        ("lookup.js", b"const value = lookup[key]", "dynamic bracket property access"),
        (
            "optional-lookup.js",
            b"target?.[candidate] = value",
            "dynamic bracket property access",
        ),
        ("iteration.js", b"for (const key in payload) use(key)", "inherited-property iteration"),
        (
            "inline.html",
            b"<script>const value = lookup[key]</script>",
            "dynamic bracket property access",
        ),
    ),
)
def test_client_technology_inventory_rejects_legacy_or_unreviewed_artifacts(
    tmp_path: Path,
    filename: str,
    content: bytes,
    message: str,
) -> None:
    project_root = _client_tree(tmp_path)
    (project_root / CLIENT_SURFACE_ROOTS[0] / filename).write_bytes(content)

    with pytest.raises(ValueError, match=message):
        validate_client_technologies(project_root)


def test_client_technology_inventory_rejects_missing_reviewed_root(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="missing production client root"):
        validate_client_technologies(tmp_path)


def test_client_technology_inventory_rejects_unreviewed_production_root(tmp_path: Path) -> None:
    project_root = _client_tree(tmp_path)
    (project_root / "new_client" / "static").mkdir(parents=True)

    with pytest.raises(ValueError, match="unreviewed production client root"):
        validate_client_technologies(project_root)


def test_javascript_object_safety_policy_accepts_map_and_set_lookups(tmp_path: Path) -> None:
    project_root = _client_tree(tmp_path)
    safe_script = project_root / CLIENT_SURFACE_ROOTS[0] / "safe.js"
    safe_script.write_text(
        'const lookup = new Map([["safe", new Set(["value"])]]); lookup.get(candidate);',
        encoding="utf-8",
    )

    assert safe_script in validate_client_technologies(project_root)


def test_javascript_object_safety_policy_ignores_non_script_html_prose(tmp_path: Path) -> None:
    project_root = _client_tree(tmp_path)
    prose = project_root / CLIENT_SURFACE_ROOTS[0] / "prose.html"
    prose.write_text("<p>A prototype can be reviewed safely.</p>", encoding="utf-8")

    assert validate_client_technologies(project_root)
