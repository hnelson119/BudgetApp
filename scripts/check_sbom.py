"""Validate the maintained CycloneDX software inventory against locked sources."""

from __future__ import annotations

import json
import sys

if __package__:
    from scripts.build_sbom import SBOM_PATH, build_sbom
else:
    from build_sbom import SBOM_PATH, build_sbom


def validate_sbom(actual: object) -> None:
    expected = build_sbom()
    if actual != expected:
        raise ValueError("docs/sbom.cdx.json is stale; run python scripts/build_sbom.py")


def main() -> int:
    try:
        actual = json.loads(SBOM_PATH.read_text(encoding="utf-8"))
        validate_sbom(actual)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"SBOM validation failed: {error}", file=sys.stderr)
        return 1
    print(f"SBOM is current and structurally complete ({len(actual['components'])} components).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
