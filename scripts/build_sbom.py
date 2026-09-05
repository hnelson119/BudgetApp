"""Build the deterministic repository-level CycloneDX software inventory."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import quote

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SBOM_PATH = PROJECT_ROOT / "docs" / "sbom.cdx.json"
PYTHON_LOCKS = ("requirements-prod.lock", "requirements-dev.lock")
IMAGE_SOURCES = (
    "Dockerfile",
    "Dockerfile.browser-tests",
    "compose.yaml",
    "compose.pentest.yaml",
    "deploy/backup/Dockerfile",
    "deploy/network/Dockerfile",
    ".github/workflows/quality.yml",
)
WORKFLOW_SOURCES = tuple(
    path.relative_to(PROJECT_ROOT).as_posix()
    for path in sorted((PROJECT_ROOT / ".github" / "workflows").glob("*.yml"))
)
TRUSTED_REPOSITORIES = {
    "docker.io",
    "github.com",
    "mcr.microsoft.com",
    "pypi.org",
    "proxy.golang.org",
    "registry.npmjs.org",
}

_PYTHON_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9_.-]+)==(?P<version>[^;\s]+)(?:;\s*(?P<marker>.+))?$"
)
_PINNED_IMAGE = re.compile(
    r"(?P<name>[a-z0-9][a-z0-9._/-]*)"
    r"(?::(?P<tag>[A-Za-z0-9][A-Za-z0-9._-]*))?"
    r"@sha256:(?P<digest>[a-f0-9]{64})"
)
_GO_MODULE = re.compile(r"(?P<name>[a-z0-9.-]+(?:/[A-Za-z0-9._-]+)+)@(?P<version>v\d+\.\d+\.\d+)")
_ACTION = re.compile(r"^(?P<name>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@(?P<revision>[a-f0-9]{40})$")


def _canonical_python_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _properties(values: dict[str, str]) -> list[dict[str, str]]:
    return [{"name": name, "value": value} for name, value in sorted(values.items())]


def _component(
    *,
    component_type: str,
    name: str,
    version: str,
    purl: str,
    scope: str,
    source_files: Iterable[str],
    source_repository: str,
    hashes: list[dict[str, str]] | None = None,
    licenses: list[dict[str, dict[str, str]]] | None = None,
    extra_properties: dict[str, str] | None = None,
) -> dict[str, Any]:
    properties = {
        "budget:source-files": ",".join(sorted(set(source_files))),
        "budget:source-repository": source_repository,
        "budget:usage-scope": scope,
    }
    if extra_properties:
        properties.update(extra_properties)
    result: dict[str, Any] = {
        "type": component_type,
        "bom-ref": purl,
        "name": name,
        "version": version,
        "purl": purl,
        "properties": _properties(properties),
    }
    if hashes:
        result["hashes"] = hashes
    if licenses:
        result["licenses"] = licenses
    return result


def _python_components() -> list[dict[str, Any]]:
    packages: dict[tuple[str, str], dict[str, Any]] = {}
    production_keys: set[tuple[str, str]] = set()
    for lock_path in PYTHON_LOCKS:
        for line_number, raw_line in enumerate(
            (PROJECT_ROOT / lock_path).read_text(encoding="utf-8").splitlines(), start=1
        ):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            match = _PYTHON_REQUIREMENT.fullmatch(line)
            if match is None:
                raise ValueError(f"{lock_path}:{line_number} is not an exact Python dependency pin")
            name = _canonical_python_name(match.group("name"))
            version = match.group("version")
            key = (name, version)
            record = packages.setdefault(key, {"files": set(), "markers": set()})
            record["files"].add(lock_path)
            if marker := match.group("marker"):
                record["markers"].add(marker)
            if lock_path == "requirements-prod.lock":
                production_keys.add(key)

    names_to_versions: dict[str, set[str]] = {}
    for name, version in packages:
        names_to_versions.setdefault(name, set()).add(version)
    conflicts = {
        name: versions for name, versions in names_to_versions.items() if len(versions) > 1
    }
    if conflicts:
        raise ValueError(f"Python lock files disagree on versions: {conflicts}")

    components: list[dict[str, Any]] = []
    for (name, version), record in sorted(packages.items()):
        extra: dict[str, str] = {}
        if record["markers"]:
            extra["budget:environment-marker"] = " or ".join(sorted(record["markers"]))
        purl = f"pkg:pypi/{quote(name, safe='')}@{quote(version, safe='')}"
        components.append(
            _component(
                component_type="library",
                name=name,
                version=version,
                purl=purl,
                scope="production" if (name, version) in production_keys else "development",
                source_files=record["files"],
                source_repository="pypi.org",
                extra_properties=extra,
            )
        )
    return components


def _npm_components() -> list[dict[str, Any]]:
    lock_path = PROJECT_ROOT / "package-lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if lock.get("lockfileVersion") != 3 or not isinstance(lock.get("packages"), dict):
        raise ValueError("package-lock.json must use npm lockfile version 3")
    components: list[dict[str, Any]] = []
    for path, package in sorted(lock["packages"].items()):
        if not path:
            continue
        if not isinstance(package, dict) or "node_modules/" not in path:
            raise ValueError(f"package-lock.json contains an unsupported package entry {path!r}")
        name = path.rsplit("node_modules/", maxsplit=1)[1]
        version = package.get("version")
        resolved = package.get("resolved")
        integrity = package.get("integrity")
        if not isinstance(version, str) or not version:
            raise ValueError(f"npm package {name!r} has no exact version")
        if not isinstance(resolved, str) or not resolved.startswith("https://registry.npmjs.org/"):
            raise ValueError(f"npm package {name!r} is not resolved from the approved registry")
        if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
            raise ValueError(f"npm package {name!r} has no SHA-512 integrity pin")
        try:
            digest = base64.b64decode(integrity.removeprefix("sha512-"), validate=True).hex()
        except ValueError as error:
            raise ValueError(f"npm package {name!r} has invalid integrity data") from error
        license_name = package.get("license")
        licenses = None
        if isinstance(license_name, str) and license_name:
            licenses = [{"license": {"id": license_name}}]
        purl = f"pkg:npm/{quote(name, safe='/')}@{quote(version, safe='')}"
        components.append(
            _component(
                component_type="library",
                name=name,
                version=version,
                purl=purl,
                scope="development",
                source_files=["package-lock.json"],
                source_repository="registry.npmjs.org",
                hashes=[{"alg": "SHA-512", "content": digest}],
                licenses=licenses,
                extra_properties={"budget:resolved-url": resolved},
            )
        )
    return components


def _image_repository(name: str) -> str:
    first_segment = name.split("/", maxsplit=1)[0]
    if "." in first_segment or ":" in first_segment:
        return first_segment
    return "docker.io"


def _image_components() -> list[dict[str, Any]]:
    images: dict[tuple[str, str, str], set[str]] = {}
    for source_file in IMAGE_SOURCES:
        source = (PROJECT_ROOT / source_file).read_text(encoding="utf-8")
        for match in _PINNED_IMAGE.finditer(source):
            name = match.group("name")
            digest = match.group("digest")
            version = match.group("tag") or f"sha256:{digest}"
            images.setdefault((name, version, digest), set()).add(source_file)
    components: list[dict[str, Any]] = []
    for (name, version, digest), source_files in sorted(images.items()):
        purl = f"pkg:oci/{quote(name, safe='/')}@{quote(version, safe='')}"
        components.append(
            _component(
                component_type="container",
                name=name,
                version=version,
                purl=purl,
                scope="production" if "compose.yaml" in source_files else "build-and-test",
                source_files=source_files,
                source_repository=_image_repository(name),
                hashes=[{"alg": "SHA-256", "content": digest}],
            )
        )
    return components


def _backup_build_components() -> list[dict[str, Any]]:
    source_file = "deploy/backup/Dockerfile"
    source = (PROJECT_ROOT / source_file).read_text(encoding="utf-8")
    modules = {
        (match.group("name"), match.group("version")) for match in _GO_MODULE.finditer(source)
    }
    components = [
        _component(
            component_type="library",
            name=name,
            version=version,
            purl=f"pkg:golang/{quote(name, safe='/')}@{quote(version, safe='')}",
            scope="production",
            source_files=[source_file],
            source_repository="proxy.golang.org",
        )
        for name, version in sorted(modules)
    ]
    version_match = re.search(r"^ARG RESTIC_VERSION=(\S+)$", source, flags=re.MULTILINE)
    digest_match = re.search(r"^ARG RESTIC_SHA256=([a-f0-9]{64})$", source, flags=re.MULTILINE)
    if version_match is None or digest_match is None:
        raise ValueError("the Restic source version and checksum must remain pinned")
    version = version_match.group(1)
    components.append(
        _component(
            component_type="application",
            name="restic",
            version=version,
            purl=f"pkg:github/restic/restic@v{quote(version, safe='')}",
            scope="production",
            source_files=[source_file],
            source_repository="github.com",
            hashes=[{"alg": "SHA-256", "content": digest_match.group(1)}],
        )
    )
    return components


def _find_uses(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "uses" and isinstance(child, str):
                yield child
            yield from _find_uses(child)
    elif isinstance(value, list):
        for child in value:
            yield from _find_uses(child)


def _action_components() -> list[dict[str, Any]]:
    actions: dict[tuple[str, str], set[str]] = {}
    for source_file in WORKFLOW_SOURCES:
        workflow = yaml.safe_load((PROJECT_ROOT / source_file).read_text(encoding="utf-8"))
        for use in _find_uses(workflow):
            match = _ACTION.fullmatch(use)
            if match is None:
                raise ValueError(f"{source_file} uses an unpinned or unsupported action {use!r}")
            key = (match.group("name"), match.group("revision"))
            actions.setdefault(key, set()).add(source_file)
    return [
        _component(
            component_type="application",
            name=name,
            version=revision,
            purl=f"pkg:github/{quote(name, safe='/')}@{revision}",
            scope="build-and-test",
            source_files=source_files,
            source_repository="github.com",
        )
        for (name, revision), source_files in sorted(actions.items())
    ]


def build_sbom() -> dict[str, Any]:
    components = [
        *_python_components(),
        *_npm_components(),
        *_image_components(),
        *_backup_build_components(),
        *_action_components(),
    ]
    components.sort(key=lambda component: component["bom-ref"])
    references = [component["bom-ref"] for component in components]
    if len(references) != len(set(references)):
        raise ValueError("software inventory contains duplicate component references")
    repositories = {
        property_["value"]
        for component in components
        for property_ in component["properties"]
        if property_["name"] == "budget:source-repository"
    }
    if repositories != TRUSTED_REPOSITORIES:
        raise ValueError("software inventory trusted-repository coverage changed")

    fingerprint = hashlib.sha256(
        json.dumps(components, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    project_purl = "pkg:pypi/household-budget@0.1.0"
    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, fingerprint)}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": project_purl,
                "name": "household-budget",
                "version": "0.1.0",
                "purl": project_purl,
            },
            "properties": _properties(
                {
                    "budget:inventory-fingerprint-sha256": fingerprint,
                    "budget:maintenance-procedure": "docs/SBOM.md",
                    "budget:scope": "production,development,build,test,and CI inputs",
                }
            ),
        },
        "components": components,
        "dependencies": [{"ref": project_purl, "dependsOn": references}],
    }


def main() -> int:
    try:
        sbom = build_sbom()
        SBOM_PATH.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as error:
        print(f"SBOM generation failed: {error}")
        return 1
    print(f"Wrote {SBOM_PATH.relative_to(PROJECT_ROOT)} with {len(sbom['components'])} components.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
