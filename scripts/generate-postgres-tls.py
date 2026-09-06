"""Generate an offline PostgreSQL CA and deployment server certificate."""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

_CA_CERTIFICATE = "postgres_ca_certificate"
_CA_PRIVATE_KEY = "postgres_ca_private_key"  # pragma: allowlist secret
_SERVER_CERTIFICATE = "postgres_server_certificate"
_SERVER_PRIVATE_KEY = "postgres_server_private_key"  # pragma: allowlist secret


class GenerationFailure(RuntimeError):
    pass


def _prepare_directory(path: Path, *, label: str) -> Path:
    if path.is_symlink():
        raise GenerationFailure(f"The {label} directory must not be a symbolic link.")
    path = path.resolve()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise GenerationFailure(f"The {label} directory is not a real directory.")
    if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise GenerationFailure(f"The {label} directory must have mode 0700.")
    return path


def _run_openssl(*arguments: str) -> None:
    try:
        completed = subprocess.run(
            ["openssl", *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise GenerationFailure("OpenSSL could not complete certificate generation.") from error
    if completed.returncode != 0:
        raise GenerationFailure("OpenSSL rejected the PostgreSQL certificate configuration.")


def _write_all(descriptor: int, payload: bytes) -> None:
    remaining = memoryview(payload)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise OSError("Certificate installation did not make progress.")
        remaining = remaining[written:]


def _install_exclusive(source: Path, destination: Path, *, mode: int, group_id: int) -> None:
    payload = source.read_bytes()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, mode)
    completed = False
    try:
        _write_all(descriptor, payload)
        if os.name != "nt":
            fchmod = getattr(os, "fchmod", None)
            fchown = getattr(os, "fchown", None)
            if fchmod is None or fchown is None:
                raise GenerationFailure("POSIX certificate permissions are unavailable.")
            fchown(descriptor, -1, group_id)
            fchmod(descriptor, mode)
        os.fsync(descriptor)
        completed = True
    finally:
        os.close(descriptor)
        if not completed:
            destination.unlink(missing_ok=True)


def generate_postgres_tls(
    *, authority_directory: Path, deployment_directory: Path, secret_group_id: int
) -> tuple[Path, ...]:
    if secret_group_id <= 0:
        raise GenerationFailure("The deployment secret group must be a non-root numeric GID.")
    authority_directory = _prepare_directory(authority_directory, label="authority")
    deployment_directory = _prepare_directory(deployment_directory, label="deployment")
    destinations = (
        authority_directory / _CA_PRIVATE_KEY,
        authority_directory / _CA_CERTIFICATE,
        deployment_directory / _CA_CERTIFICATE,
        deployment_directory / _SERVER_CERTIFICATE,
        deployment_directory / _SERVER_PRIVATE_KEY,
    )
    if any(path.exists() or path.is_symlink() for path in destinations):
        raise GenerationFailure(
            "A PostgreSQL TLS output already exists; use a new staging directory."
        )

    created: list[Path] = []
    try:
        with tempfile.TemporaryDirectory(prefix="budgetapp-postgres-tls-") as temporary_name:
            temporary = Path(temporary_name)
            ca_key = temporary / "ca.key"
            ca_certificate = temporary / "ca.crt"
            server_key = temporary / "server.key"
            server_request = temporary / "server.csr"
            server_certificate = temporary / "server.crt"
            server_extensions = temporary / "server.ext"
            server_extensions.write_text(
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature\n"
                "extendedKeyUsage=serverAuth\n"
                "subjectAltName=DNS:db\n"
                "subjectKeyIdentifier=hash\n"
                "authorityKeyIdentifier=keyid,issuer\n",
                encoding="ascii",
            )

            _run_openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ca_key))
            _run_openssl(
                "req",
                "-x509",
                "-new",
                "-sha256",
                "-days",
                "3650",
                "-key",
                str(ca_key),
                "-out",
                str(ca_certificate),
                "-subj",
                "/CN=Household Budget PostgreSQL Offline CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-addext",
                "subjectKeyIdentifier=hash",
            )
            _run_openssl(
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                str(server_key),
            )
            _run_openssl(
                "req",
                "-new",
                "-sha256",
                "-key",
                str(server_key),
                "-out",
                str(server_request),
                "-subj",
                "/CN=db",
            )
            _run_openssl(
                "x509",
                "-req",
                "-sha256",
                "-days",
                "397",
                "-in",
                str(server_request),
                "-CA",
                str(ca_certificate),
                "-CAkey",
                str(ca_key),
                "-set_serial",
                f"0x{secrets.token_hex(20)}",
                "-extfile",
                str(server_extensions),
                "-out",
                str(server_certificate),
            )
            _run_openssl(
                "verify",
                "-CAfile",
                str(ca_certificate),
                "-purpose",
                "sslserver",
                "-verify_hostname",
                "db",
                str(server_certificate),
            )
            _run_openssl("x509", "-checkend", "2592000", "-noout", "-in", str(server_certificate))
            _run_openssl("pkey", "-check", "-noout", "-in", str(ca_key))
            _run_openssl("pkey", "-check", "-noout", "-in", str(server_key))

            install_plan = (
                (ca_key, destinations[0], 0o600, os.getgid() if os.name != "nt" else 1),
                (ca_certificate, destinations[1], 0o644, os.getgid() if os.name != "nt" else 1),
                (ca_certificate, destinations[2], 0o440, secret_group_id),
                (server_certificate, destinations[3], 0o440, secret_group_id),
                (server_key, destinations[4], 0o440, secret_group_id),
            )
            for source, destination, mode, group_id in install_plan:
                _install_exclusive(source, destination, mode=mode, group_id=group_id)
                created.append(destination)
    except (GenerationFailure, OSError):
        for path in reversed(created):
            path.unlink(missing_ok=True)
        raise
    return destinations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authority-directory", type=Path, required=True)
    parser.add_argument("--deployment-directory", type=Path, required=True)
    parser.add_argument("--secret-group-id", type=int, required=True)
    arguments = parser.parse_args()
    if shutil.which("openssl") is None:
        parser.error("OpenSSL is required for PostgreSQL TLS generation.")
    try:
        generate_postgres_tls(
            authority_directory=arguments.authority_directory,
            deployment_directory=arguments.deployment_directory,
            secret_group_id=arguments.secret_group_id,
        )
    except GenerationFailure as error:
        parser.error(str(error))
    print("Generated PostgreSQL TLS material without printing private values.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
