"""Reject unsupported or legacy technologies from the production browser surface."""

from __future__ import annotations

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CLIENT_SURFACE_ROOTS = (
    "audit/templates",
    "budgets/templates",
    "core/static",
    "core/templates",
    "debts/templates",
    "goals/templates",
    "identity/templates",
    "imports/templates",
    "notifications/templates",
    "spending/templates",
)
TEXT_SUFFIXES = frozenset({".css", ".html", ".js", ".json", ".svg", ".webmanifest"})
BINARY_SUFFIXES = frozenset(
    {".gif", ".ico", ".jpeg", ".jpg", ".otf", ".png", ".ttf", ".wasm", ".webp", ".woff", ".woff2"}
)
LEGACY_SUFFIXES = frozenset(
    {
        ".cab",
        ".class",
        ".dcr",
        ".dir",
        ".dxr",
        ".jar",
        ".nexe",
        ".ocx",
        ".pexe",
        ".spl",
        ".swf",
        ".xap",
    }
)
MAX_TEXT_ASSET_BYTES = 2_000_000
LEGACY_PATTERNS = (
    ("plug-in element", re.compile(r"<\s*(?:applet|embed|object)\b", re.IGNORECASE)),
    ("ActiveX class identifier", re.compile(r"\bclassid\s*=", re.IGNORECASE)),
    (
        "legacy plug-in media type",
        re.compile(
            r"application/(?:x-java-applet|x-nacl|x-pnacl|x-shockwave-flash|x-silverlight)",
            re.IGNORECASE,
        ),
    ),
    ("ActiveX API", re.compile(r"\bActiveXObject\s*\(", re.IGNORECASE)),
    (
        "browser plug-in enumeration",
        re.compile(r"\bnavigator\s*\.\s*(?:mimeTypes|plugins)\b", re.IGNORECASE),
    ),
    (
        "legacy client artifact reference",
        re.compile(
            r"\.(?:cab|class|dcr|dir|dxr|jar|nexe|ocx|pexe|spl|swf|xap)"
            r"(?:[?#\"'\s)]|$)",
            re.IGNORECASE,
        ),
    ),
)


def production_client_files(project_root: Path = PROJECT_ROOT) -> list[Path]:
    expected_roots = set(CLIENT_SURFACE_ROOTS)
    discovered_roots = {
        f"{child.name}/{directory_name}"
        for child in project_root.iterdir()
        if child.is_dir()
        for directory_name in ("static", "templates")
        if (child / directory_name).is_dir()
    }
    discovered_roots.update(
        directory_name
        for directory_name in ("static", "templates")
        if (project_root / directory_name).is_dir()
    )
    unreviewed_roots = discovered_roots - expected_roots
    if unreviewed_roots:
        raise ValueError(
            "unreviewed production client root: " + ", ".join(sorted(unreviewed_roots))
        )

    files: list[Path] = []
    for relative_root in CLIENT_SURFACE_ROOTS:
        root = project_root / relative_root
        if not root.is_dir():
            raise ValueError(f"missing production client root: {relative_root}")
        if root.is_symlink():
            raise ValueError(f"production client roots cannot be symlinks: {relative_root}")
        files.extend(path for path in root.rglob("*") if path.is_file() or path.is_symlink())
    return sorted(files)


def validate_client_technologies(project_root: Path = PROJECT_ROOT) -> list[Path]:
    files = production_client_files(project_root)
    if not files:
        raise ValueError("the production client surface is empty")

    allowed_suffixes = TEXT_SUFFIXES | BINARY_SUFFIXES
    for path in files:
        relative_path = path.relative_to(project_root).as_posix()
        if path.is_symlink():
            raise ValueError(f"production client symlinks require security review: {relative_path}")
        suffix = path.suffix.casefold()
        if suffix in LEGACY_SUFFIXES:
            raise ValueError(f"legacy client artifact is prohibited: {relative_path}")
        if suffix not in allowed_suffixes:
            raise ValueError(f"unreviewed production client artifact type: {relative_path}")
        if suffix not in TEXT_SUFFIXES:
            continue
        if path.stat().st_size > MAX_TEXT_ASSET_BYTES:
            raise ValueError(
                f"production client text artifact is unexpectedly large: {relative_path}"
            )
        content = path.read_text(encoding="utf-8")
        for description, pattern in LEGACY_PATTERNS:
            if pattern.search(content):
                raise ValueError(f"{description} is prohibited in {relative_path}")
    return files


def main() -> int:
    try:
        files = validate_client_technologies()
    except (OSError, UnicodeError, ValueError) as error:
        print(f"Client technology validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "Production client technology inventory passed "
        f"({len(files)} artifacts; native HTML, CSS, and JavaScript only)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
