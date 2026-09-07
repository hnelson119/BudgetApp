"""Generate offline authorities and leaf certificates for internal production TLS."""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

_SERVER_CA_CERTIFICATE = "postgres_ca_certificate"
_SERVER_CA_PRIVATE_KEY = "postgres_ca_private_key"  # pragma: allowlist secret
_CLIENT_CA_CERTIFICATE = "postgres_client_ca_certificate"
_CLIENT_CA_PRIVATE_KEY = "postgres_client_ca_private_key"  # pragma: allowlist secret
_SERVER_CERTIFICATE = "postgres_server_certificate"
_SERVER_PRIVATE_KEY = "postgres_server_private_key"  # pragma: allowlist secret
_GUNICORN_SERVER_CA_CERTIFICATE = "gunicorn_ca_certificate"
_GUNICORN_SERVER_CA_PRIVATE_KEY = "gunicorn_ca_private_key"  # pragma: allowlist secret
_GUNICORN_CLIENT_CA_CERTIFICATE = "gunicorn_client_ca_certificate"
_GUNICORN_CLIENT_CA_PRIVATE_KEY = "gunicorn_client_ca_private_key"  # pragma: allowlist secret
_GUNICORN_SERVER_CERTIFICATE = "gunicorn_server_certificate"
_GUNICORN_SERVER_PRIVATE_KEY = "gunicorn_server_private_key"  # pragma: allowlist secret
_NGINX_CLIENT_CERTIFICATE = "nginx_client_certificate"
_NGINX_CLIENT_PRIVATE_KEY = "nginx_client_private_key"  # pragma: allowlist secret

CLIENT_IDENTITIES = (
    ("postgres_db_bootstrap_client", "budget-db-bootstrap"),
    ("postgres_migrate_client", "budget-migrate"),
    ("postgres_mfa_key_rotate_client", "budget-mfa-key-rotate"),
    ("postgres_backup_client", "budget-backup"),
    ("postgres_integrity_client", "budget-integrity"),
    ("postgres_notify_client", "budget-notify"),
    ("postgres_import_cleanup_client", "budget-import-cleanup"),
    ("postgres_restore_verify_client", "budget-restore-verify"),
    ("postgres_web_client", "budget-web"),
)


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
        raise GenerationFailure("OpenSSL rejected the internal TLS certificate configuration.")


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


def _generate_ca(*, key: Path, certificate: Path, common_name: str) -> None:
    _run_openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key))
    _run_openssl(
        "req",
        "-x509",
        "-new",
        "-sha256",
        "-days",
        "3650",
        "-key",
        str(key),
        "-out",
        str(certificate),
        "-subj",
        f"/CN={common_name}",
        "-addext",
        "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-addext",
        "subjectKeyIdentifier=hash",
    )
    _run_openssl("pkey", "-check", "-noout", "-in", str(key))


def _issue_certificate(
    *,
    ca_key: Path,
    ca_certificate: Path,
    key: Path,
    request: Path,
    certificate: Path,
    extensions: Path,
    common_name: str,
    purpose: str,
) -> None:
    _run_openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key))
    _run_openssl(
        "req",
        "-new",
        "-sha256",
        "-key",
        str(key),
        "-out",
        str(request),
        "-subj",
        f"/CN={common_name}",
    )
    _run_openssl(
        "x509",
        "-req",
        "-sha256",
        "-days",
        "397",
        "-in",
        str(request),
        "-CA",
        str(ca_certificate),
        "-CAkey",
        str(ca_key),
        "-set_serial",
        f"0x{secrets.token_hex(20)}",
        "-extfile",
        str(extensions),
        "-out",
        str(certificate),
    )
    verify_arguments = [
        "verify",
        "-CAfile",
        str(ca_certificate),
        "-purpose",
        purpose,
    ]
    if purpose == "sslserver":
        verify_arguments.extend(("-verify_hostname", common_name))
    verify_arguments.append(str(certificate))
    _run_openssl(*verify_arguments)
    _run_openssl("x509", "-checkend", "2592000", "-noout", "-in", str(certificate))
    _run_openssl("pkey", "-check", "-noout", "-in", str(key))


def generate_internal_tls(
    *, authority_directory: Path, deployment_directory: Path, secret_group_id: int
) -> tuple[Path, ...]:
    if secret_group_id <= 0:
        raise GenerationFailure("The deployment secret group must be a non-root numeric GID.")
    authority_directory = _prepare_directory(authority_directory, label="authority")
    deployment_directory = _prepare_directory(deployment_directory, label="deployment")

    authority_destinations = (
        authority_directory / _SERVER_CA_PRIVATE_KEY,
        authority_directory / _SERVER_CA_CERTIFICATE,
        authority_directory / _CLIENT_CA_PRIVATE_KEY,
        authority_directory / _CLIENT_CA_CERTIFICATE,
        authority_directory / _GUNICORN_SERVER_CA_PRIVATE_KEY,
        authority_directory / _GUNICORN_SERVER_CA_CERTIFICATE,
        authority_directory / _GUNICORN_CLIENT_CA_PRIVATE_KEY,
        authority_directory / _GUNICORN_CLIENT_CA_CERTIFICATE,
    )
    deployment_destinations = (
        deployment_directory / _SERVER_CA_CERTIFICATE,
        deployment_directory / _CLIENT_CA_CERTIFICATE,
        deployment_directory / _SERVER_CERTIFICATE,
        deployment_directory / _SERVER_PRIVATE_KEY,
        *(
            deployment_directory / f"{prefix}_{kind}"
            for prefix, _common_name in CLIENT_IDENTITIES
            for kind in ("certificate", "private_key")
        ),
        deployment_directory / _GUNICORN_SERVER_CA_CERTIFICATE,
        deployment_directory / _GUNICORN_CLIENT_CA_CERTIFICATE,
        deployment_directory / _GUNICORN_SERVER_CERTIFICATE,
        deployment_directory / _GUNICORN_SERVER_PRIVATE_KEY,
        deployment_directory / _NGINX_CLIENT_CERTIFICATE,
        deployment_directory / _NGINX_CLIENT_PRIVATE_KEY,
    )
    destinations = (*authority_destinations, *deployment_destinations)
    if any(path.exists() or path.is_symlink() for path in destinations):
        raise GenerationFailure(
            "An internal TLS output already exists; use a new staging directory."
        )

    created: list[Path] = []
    try:
        with tempfile.TemporaryDirectory(prefix="budgetapp-postgres-tls-") as temporary_name:
            temporary = Path(temporary_name)
            server_ca_key = temporary / "server-ca.key"
            server_ca_certificate = temporary / "server-ca.crt"
            client_ca_key = temporary / "client-ca.key"
            client_ca_certificate = temporary / "client-ca.crt"
            server_key = temporary / "server.key"
            server_request = temporary / "server.csr"
            server_certificate = temporary / "server.crt"
            server_extensions = temporary / "server.ext"
            client_extensions = temporary / "client.ext"
            gunicorn_server_ca_key = temporary / "gunicorn-server-ca.key"
            gunicorn_server_ca_certificate = temporary / "gunicorn-server-ca.crt"
            gunicorn_client_ca_key = temporary / "gunicorn-client-ca.key"
            gunicorn_client_ca_certificate = temporary / "gunicorn-client-ca.crt"
            gunicorn_server_key = temporary / "gunicorn-server.key"
            gunicorn_server_request = temporary / "gunicorn-server.csr"
            gunicorn_server_certificate = temporary / "gunicorn-server.crt"
            gunicorn_server_extensions = temporary / "gunicorn-server.ext"
            nginx_client_key = temporary / "nginx-client.key"
            nginx_client_request = temporary / "nginx-client.csr"
            nginx_client_certificate = temporary / "nginx-client.crt"
            server_extensions.write_text(
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature\n"
                "extendedKeyUsage=serverAuth\n"
                "subjectAltName=DNS:db\n"
                "subjectKeyIdentifier=hash\n"
                "authorityKeyIdentifier=keyid,issuer\n",
                encoding="ascii",
            )
            client_extensions.write_text(
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature\n"
                "extendedKeyUsage=clientAuth\n"
                "subjectKeyIdentifier=hash\n"
                "authorityKeyIdentifier=keyid,issuer\n",
                encoding="ascii",
            )
            gunicorn_server_extensions.write_text(
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature\n"
                "extendedKeyUsage=serverAuth\n"
                "subjectAltName=DNS:web\n"
                "subjectKeyIdentifier=hash\n"
                "authorityKeyIdentifier=keyid,issuer\n",
                encoding="ascii",
            )

            _generate_ca(
                key=server_ca_key,
                certificate=server_ca_certificate,
                common_name="Household Budget PostgreSQL Server CA",
            )
            _generate_ca(
                key=client_ca_key,
                certificate=client_ca_certificate,
                common_name="Household Budget PostgreSQL Client CA",
            )
            _generate_ca(
                key=gunicorn_server_ca_key,
                certificate=gunicorn_server_ca_certificate,
                common_name="Household Budget Gunicorn Server CA",
            )
            _generate_ca(
                key=gunicorn_client_ca_key,
                certificate=gunicorn_client_ca_certificate,
                common_name="Household Budget Nginx Client CA",
            )
            _issue_certificate(
                ca_key=server_ca_key,
                ca_certificate=server_ca_certificate,
                key=server_key,
                request=server_request,
                certificate=server_certificate,
                extensions=server_extensions,
                common_name="db",
                purpose="sslserver",
            )

            client_material: list[tuple[Path, Path]] = []
            for prefix, common_name in CLIENT_IDENTITIES:
                client_key = temporary / f"{prefix}.key"
                client_request = temporary / f"{prefix}.csr"
                client_certificate = temporary / f"{prefix}.crt"
                _issue_certificate(
                    ca_key=client_ca_key,
                    ca_certificate=client_ca_certificate,
                    key=client_key,
                    request=client_request,
                    certificate=client_certificate,
                    extensions=client_extensions,
                    common_name=common_name,
                    purpose="sslclient",
                )
                client_material.append((client_certificate, client_key))

            _issue_certificate(
                ca_key=gunicorn_server_ca_key,
                ca_certificate=gunicorn_server_ca_certificate,
                key=gunicorn_server_key,
                request=gunicorn_server_request,
                certificate=gunicorn_server_certificate,
                extensions=gunicorn_server_extensions,
                common_name="web",
                purpose="sslserver",
            )
            _issue_certificate(
                ca_key=gunicorn_client_ca_key,
                ca_certificate=gunicorn_client_ca_certificate,
                key=nginx_client_key,
                request=nginx_client_request,
                certificate=nginx_client_certificate,
                extensions=client_extensions,
                common_name="budget-ingress",
                purpose="sslclient",
            )

            local_group_id = os.getgid() if os.name != "nt" else 1
            gunicorn_destination_index = 4 + (len(CLIENT_IDENTITIES) * 2)
            install_plan = [
                (server_ca_key, authority_destinations[0], 0o600, local_group_id),
                (server_ca_certificate, authority_destinations[1], 0o644, local_group_id),
                (client_ca_key, authority_destinations[2], 0o600, local_group_id),
                (client_ca_certificate, authority_destinations[3], 0o644, local_group_id),
                (server_ca_certificate, deployment_destinations[0], 0o440, secret_group_id),
                (client_ca_certificate, deployment_destinations[1], 0o440, secret_group_id),
                (server_certificate, deployment_destinations[2], 0o440, secret_group_id),
                (server_key, deployment_destinations[3], 0o440, secret_group_id),
                (gunicorn_server_ca_key, authority_destinations[4], 0o600, local_group_id),
                (
                    gunicorn_server_ca_certificate,
                    authority_destinations[5],
                    0o644,
                    local_group_id,
                ),
                (gunicorn_client_ca_key, authority_destinations[6], 0o600, local_group_id),
                (
                    gunicorn_client_ca_certificate,
                    authority_destinations[7],
                    0o644,
                    local_group_id,
                ),
            ]
            for index, (client_certificate, client_key) in enumerate(client_material):
                destination_index = 4 + (index * 2)
                install_plan.extend(
                    (
                        (
                            client_certificate,
                            deployment_destinations[destination_index],
                            0o440,
                            secret_group_id,
                        ),
                        (
                            client_key,
                            deployment_destinations[destination_index + 1],
                            0o440,
                            secret_group_id,
                        ),
                    )
                )
            install_plan.extend(
                (
                    (
                        gunicorn_server_ca_certificate,
                        deployment_destinations[gunicorn_destination_index],
                        0o440,
                        secret_group_id,
                    ),
                    (
                        gunicorn_client_ca_certificate,
                        deployment_destinations[gunicorn_destination_index + 1],
                        0o440,
                        secret_group_id,
                    ),
                    (
                        gunicorn_server_certificate,
                        deployment_destinations[gunicorn_destination_index + 2],
                        0o440,
                        secret_group_id,
                    ),
                    (
                        gunicorn_server_key,
                        deployment_destinations[gunicorn_destination_index + 3],
                        0o440,
                        secret_group_id,
                    ),
                    (
                        nginx_client_certificate,
                        deployment_destinations[gunicorn_destination_index + 4],
                        0o440,
                        secret_group_id,
                    ),
                    (
                        nginx_client_key,
                        deployment_destinations[gunicorn_destination_index + 5],
                        0o440,
                        secret_group_id,
                    ),
                )
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
        parser.error("OpenSSL is required for internal TLS generation.")
    try:
        generate_internal_tls(
            authority_directory=arguments.authority_directory,
            deployment_directory=arguments.deployment_directory,
            secret_group_id=arguments.secret_group_id,
        )
    except GenerationFailure as error:
        parser.error(str(error))
    print("Generated internal TLS material without printing private values.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
