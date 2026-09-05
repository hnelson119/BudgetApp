"""Fail when detect-secrets finds a likely secret in project-owned text files."""

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

_ASVS_SOURCE_SHA256 = "".join(
    (
        "8201b20eec2908c3",  # pragma: allowlist secret
        "380ac600c91c8ba7",  # pragma: allowlist secret
        "46346fbb80885936",  # pragma: allowlist secret
        "6abb232027532311",  # pragma: allowlist secret
    )
)
_ASVS_SOURCE_GIT_BLOB = "".join(
    (
        "f7ae2926598c4648",  # pragma: allowlist secret
        "ff7614a6968e4c8f",  # pragma: allowlist secret
        "d89524bd",
    )
)
_ASVS_CATALOG_SHA256 = "".join(
    (
        "7baeb53026600db7",  # pragma: allowlist secret
        "6513489acaccd93b",  # pragma: allowlist secret
        "a60490e785ffad80",  # pragma: allowlist secret
        "6e2c164c474ad273",  # pragma: allowlist secret
    )
)
_PASSWORD_CORPUS_SHA256 = "".join(
    (
        "92873cd5159a599d",  # pragma: allowlist secret
        "022792393a3a76b8",  # pragma: allowlist secret
        "87da41cbbf09b4ef",  # pragma: allowlist secret
        "544b3e1386fa4627",  # pragma: allowlist secret
    )
)
_PUBLIC_FINGERPRINTS = {
    "docs/asvs-5.0.0-level2-evidence.json": {
        ("sha256", _ASVS_SOURCE_SHA256),
        ("git_blob", _ASVS_SOURCE_GIT_BLOB),
        ("catalog_sha256", _ASVS_CATALOG_SHA256),
    },
    "docs/release-evidence.json": {("source_sha256", _ASVS_SOURCE_SHA256)},
}
_APPROVED_HASH_ONLY_FILES = {
    "identity/data/breached-passwords-v1.txt": _PASSWORD_CORPUS_SHA256,
}
_SBOM_HASH_LINE = re.compile(r'^\s*"(?:content|value)": "[0-9a-f]{64}(?:[0-9a-f]{64})?",?\s*$')
_SBOM_REVISION_LINE = re.compile(r'^\s*"version": "[0-9a-f]{40}",?\s*$')


def _is_approved_public_fingerprint(file_name: str, line: str) -> bool:
    normalized_name = file_name.replace("\\", "/")
    if normalized_name == "docs/sbom.cdx.json" and (
        _SBOM_HASH_LINE.fullmatch(line) or _SBOM_REVISION_LINE.fullmatch(line)
    ):
        return True
    return any(
        f'"{field}": "{value}"' in line
        for field, value in _PUBLIC_FINGERPRINTS.get(normalized_name, set())
    )


def _is_approved_hash_only_file(file_name: str, content: bytes) -> bool:
    normalized_name = file_name.replace("\\", "/")
    expected_digest = _APPROVED_HASH_ONLY_FILES.get(normalized_name)
    return expected_digest is not None and hashlib.sha256(content).hexdigest() == expected_digest


def main() -> int:
    command = [
        sys.executable,
        "-m",
        "detect_secrets",
        "scan",
        "--all-files",
        "--exclude-files",
        (
            r"(^|[\\/])(\.git|\.venv|\.mypy_cache|\.pytest_cache|\.pytest-tmp|\.ruff_cache|"
            r"design[\\/]mockups)([\\/]|$)|db\.sqlite3$"
        ),
    ]
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        print(completed.stderr or "Secret scanner failed.", file=sys.stderr)
        return completed.returncode

    results = json.loads(completed.stdout).get("results", {})
    filtered_results: dict[str, list[dict[str, object]]] = {}
    for file_name, findings in results.items():
        file_path = Path(file_name)
        content = file_path.read_bytes()
        if _is_approved_hash_only_file(file_name, content):
            continue
        lines = content.decode("utf-8").splitlines()
        retained = [
            finding
            for finding in findings
            if not _is_approved_public_fingerprint(
                file_name,
                lines[int(finding["line_number"]) - 1],
            )
        ]
        if retained:
            filtered_results[file_name] = retained
    results = filtered_results
    if results:
        print("Potential secrets detected:", file=sys.stderr)
        for file_name, findings in sorted(results.items()):
            line_numbers = ", ".join(str(finding["line_number"]) for finding in findings)
            print(f"  {file_name}: line(s) {line_numbers}", file=sys.stderr)
        return 1

    print("Secret scan passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
