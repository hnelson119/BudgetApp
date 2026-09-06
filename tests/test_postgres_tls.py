import importlib.util
import os
import stat
from pathlib import Path
from types import ModuleType

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _load_generator() -> ModuleType:
    specification = importlib.util.spec_from_file_location(
        "postgres_tls_generator", PROJECT_ROOT / "scripts" / "generate-postgres-tls.py"
    )
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


GENERATOR = _load_generator()


def _fake_openssl(*arguments: str) -> None:
    if "-out" not in arguments:
        return
    output = Path(arguments[arguments.index("-out") + 1])
    output.write_bytes(f"generated:{output.name}".encode("ascii"))


def test_generator_separates_offline_authority_from_deployment_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = tmp_path / "offline-authority"
    deployment = tmp_path / "deployment-secrets"
    group_id = os.getgid() if os.name != "nt" else 10002
    monkeypatch.setattr(GENERATOR, "_run_openssl", _fake_openssl)

    outputs = GENERATOR.generate_postgres_tls(
        authority_directory=authority,
        deployment_directory=deployment,
        secret_group_id=group_id,
    )

    authority_names = {
        "postgres_ca_private_key",
        "postgres_ca_certificate",
        "postgres_client_ca_private_key",
        "postgres_client_ca_certificate",
    }
    deployment_names = {
        "postgres_ca_certificate",
        "postgres_client_ca_certificate",
        "postgres_server_certificate",
        "postgres_server_private_key",
        *(
            f"{prefix}_{kind}"
            for prefix, _common_name in GENERATOR.CLIENT_IDENTITIES
            for kind in ("certificate", "private_key")
        ),
    }
    assert {path.name for path in outputs} == authority_names | deployment_names
    assert {path.name for path in authority.iterdir()} == authority_names
    assert {path.name for path in deployment.iterdir()} == deployment_names
    assert (authority / "postgres_ca_private_key").is_file()
    assert not (deployment / "postgres_ca_private_key").exists()
    assert (authority / "postgres_ca_certificate").read_bytes() == (
        deployment / "postgres_ca_certificate"
    ).read_bytes()
    assert (authority / "postgres_client_ca_certificate").read_bytes() == (
        deployment / "postgres_client_ca_certificate"
    ).read_bytes()
    assert not (deployment / "postgres_client_ca_private_key").exists()
    assert (deployment / "postgres_server_certificate").is_file()
    assert (deployment / "postgres_server_private_key").is_file()
    for prefix, _common_name in GENERATOR.CLIENT_IDENTITIES:
        assert (deployment / f"{prefix}_certificate").is_file()
        assert (deployment / f"{prefix}_private_key").is_file()
    if os.name != "nt":
        assert stat.S_IMODE((authority / "postgres_ca_private_key").stat().st_mode) == 0o600
        assert stat.S_IMODE((authority / "postgres_ca_certificate").stat().st_mode) == 0o644
        assert stat.S_IMODE((authority / "postgres_client_ca_private_key").stat().st_mode) == 0o600
        assert stat.S_IMODE((authority / "postgres_client_ca_certificate").stat().st_mode) == 0o644
        for name in deployment_names:
            assert stat.S_IMODE((deployment / name).stat().st_mode) == 0o440

    with pytest.raises(GENERATOR.GenerationFailure, match="already exists"):
        GENERATOR.generate_postgres_tls(
            authority_directory=authority,
            deployment_directory=deployment,
            secret_group_id=group_id,
        )


def test_generator_refuses_root_secret_group(tmp_path: Path) -> None:
    with pytest.raises(GENERATOR.GenerationFailure, match="non-root numeric GID"):
        GENERATOR.generate_postgres_tls(
            authority_directory=tmp_path / "authority",
            deployment_directory=tmp_path / "deployment",
            secret_group_id=0,
        )


def test_generator_removes_partial_deployment_outputs_after_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = tmp_path / "authority"
    deployment = tmp_path / "deployment"
    group_id = os.getgid() if os.name != "nt" else 10002
    install = GENERATOR._install_exclusive
    calls = 0

    def fail_during_install(source: Path, destination: Path, *, mode: int, group_id: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise GENERATOR.GenerationFailure("injected failure")
        install(source, destination, mode=mode, group_id=group_id)

    monkeypatch.setattr(GENERATOR, "_run_openssl", _fake_openssl)
    monkeypatch.setattr(GENERATOR, "_install_exclusive", fail_during_install)

    with pytest.raises(GENERATOR.GenerationFailure, match="injected failure"):
        GENERATOR.generate_postgres_tls(
            authority_directory=authority,
            deployment_directory=deployment,
            secret_group_id=group_id,
        )

    assert not any(authority.iterdir())
    assert not any(deployment.iterdir())


def test_generator_issues_separate_purpose_bound_server_and_client_certificates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, ...]] = []

    def recording_openssl(*arguments: str) -> None:
        calls.append(arguments)
        _fake_openssl(*arguments)

    monkeypatch.setattr(GENERATOR, "_run_openssl", recording_openssl)
    GENERATOR.generate_postgres_tls(
        authority_directory=tmp_path / "authority",
        deployment_directory=tmp_path / "deployment",
        secret_group_id=os.getgid() if os.name != "nt" else 10002,
    )

    subjects = {call[call.index("-subj") + 1] for call in calls if "-subj" in call}
    assert "/CN=Household Budget PostgreSQL Server CA" in subjects
    assert "/CN=Household Budget PostgreSQL Client CA" in subjects
    assert "/CN=db" in subjects
    client_subjects = {f"/CN={common_name}" for _prefix, common_name in GENERATOR.CLIENT_IDENTITIES}
    assert client_subjects <= subjects
    assert sum(call[:1] == ("verify",) and "sslserver" in call for call in calls) == 1
    assert sum(call[:1] == ("verify",) and "sslclient" in call for call in calls) == len(
        GENERATOR.CLIENT_IDENTITIES
    )
