"""Fail when detect-secrets finds a likely secret in project-owned text files."""

import json
import subprocess
import sys


def main() -> int:
    command = [
        sys.executable,
        "-m",
        "detect_secrets",
        "scan",
        "--all-files",
        "--exclude-files",
        (
            r"(^|[\\/])(\.git|\.venv|\.mypy_cache|\.pytest_cache|\.ruff_cache|"
            r"design[\\/]mockups)([\\/]|$)|db\.sqlite3$"
        ),
    ]
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        print(completed.stderr or "Secret scanner failed.", file=sys.stderr)
        return completed.returncode

    results = json.loads(completed.stdout).get("results", {})
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
