from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Any


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enforce a branch-only coverage floor.")
    parser.add_argument(
        "--fail-under",
        type=float,
        default=80.0,
        help="Minimum covered branch percentage (default: 80).",
    )
    arguments = parser.parse_args()
    if not 0 <= arguments.fail_under <= 100:
        parser.error("--fail-under must be between 0 and 100")
    return arguments


def _coverage_totals() -> dict[str, Any]:
    result = subprocess.run(
        [sys.executable, "-m", "coverage", "json", "-o", "-"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(result.stderr or result.stdout, file=sys.stderr)
        raise SystemExit(result.returncode)
    report = json.loads(result.stdout)
    return dict(report["totals"])


def main() -> int:
    arguments = _arguments()
    totals = _coverage_totals()
    covered = int(totals["covered_branches"])
    total = int(totals["num_branches"])
    percentage = 100.0 if total == 0 else covered / total * 100
    print(f"Branch coverage: {percentage:.2f}% ({covered}/{total})")
    if percentage < arguments.fail_under:
        print(
            f"Branch coverage is below the required {arguments.fail_under:.2f}% floor.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
