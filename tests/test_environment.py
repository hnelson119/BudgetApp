from pathlib import Path

import pytest
from django.core.exceptions import ImproperlyConfigured

from config.settings.environment import (
    required_certificate_file,
    required_environment,
    required_private_key_file,
    required_secret_file,
)


def test_required_environment_rejects_missing_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REQUIRED_SETTING", raising=False)

    with pytest.raises(ImproperlyConfigured, match="REQUIRED_SETTING must be set"):
        required_environment("REQUIRED_SETTING")


def test_secret_must_not_be_supplied_as_plaintext_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TEST_SECRET", "x" * 64)

    with pytest.raises(ImproperlyConfigured, match="must not be supplied directly"):
        required_secret_file("TEST_SECRET")


def test_secret_is_read_from_mounted_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    secret_path = tmp_path / "test_secret"
    secret_path.write_text("x" * 64, encoding="utf-8")
    monkeypatch.delenv("TEST_SECRET", raising=False)
    monkeypatch.setenv("TEST_SECRET_FILE", str(secret_path))

    assert required_secret_file("TEST_SECRET") == "x" * 64


@pytest.mark.parametrize("value", ["too-short", "replace-this-placeholder-value-xxxx"])
def test_secret_rejects_weak_or_placeholder_values(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, value: str
) -> None:
    secret_path = tmp_path / "test_secret"
    secret_path.write_text(value, encoding="utf-8")
    monkeypatch.delenv("TEST_SECRET", raising=False)
    monkeypatch.setenv("TEST_SECRET_FILE", str(secret_path))

    with pytest.raises(ImproperlyConfigured):
        required_secret_file("TEST_SECRET")


def test_certificate_returns_only_a_valid_mounted_pem_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    certificate_path = tmp_path / "internal-ca.crt"
    certificate_path.write_text(
        "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n",
        encoding="ascii",
    )
    monkeypatch.delenv("TEST_CERTIFICATE", raising=False)
    monkeypatch.setenv("TEST_CERTIFICATE_FILE", str(certificate_path))

    assert required_certificate_file("TEST_CERTIFICATE") == str(certificate_path)


@pytest.mark.parametrize("value", ("not a certificate", "", "-----BEGIN CERTIFICATE-----"))
def test_certificate_rejects_malformed_mounted_content(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, value: str
) -> None:
    certificate_path = tmp_path / "internal-ca.crt"
    certificate_path.write_text(value, encoding="ascii")
    monkeypatch.delenv("TEST_CERTIFICATE", raising=False)
    monkeypatch.setenv("TEST_CERTIFICATE_FILE", str(certificate_path))

    with pytest.raises(ImproperlyConfigured):
        required_certificate_file("TEST_CERTIFICATE")


def test_certificate_must_not_be_supplied_inline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_CERTIFICATE", "inline")

    with pytest.raises(ImproperlyConfigured, match="must not be supplied directly"):
        required_certificate_file("TEST_CERTIFICATE")


def test_private_key_returns_only_a_regular_mounted_file_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    private_key_path = tmp_path / "client.key"
    private_key_path.write_bytes(b"private-key-material")
    monkeypatch.delenv("TEST_PRIVATE_KEY", raising=False)
    monkeypatch.setenv("TEST_PRIVATE_KEY_FILE", str(private_key_path))

    assert required_private_key_file("TEST_PRIVATE_KEY") == str(private_key_path)


def test_private_key_rejects_inline_empty_and_symlink_values(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("TEST_PRIVATE_KEY", "inline")
    with pytest.raises(ImproperlyConfigured, match="must not be supplied directly"):
        required_private_key_file("TEST_PRIVATE_KEY")

    monkeypatch.delenv("TEST_PRIVATE_KEY")
    empty_path = tmp_path / "empty.key"
    empty_path.touch()
    monkeypatch.setenv("TEST_PRIVATE_KEY_FILE", str(empty_path))
    with pytest.raises(ImproperlyConfigured, match="invalid size"):
        required_private_key_file("TEST_PRIVATE_KEY")

    target_path = tmp_path / "target.key"
    target_path.write_bytes(b"private-key-material")
    link_path = tmp_path / "link.key"
    try:
        link_path.symlink_to(target_path)
    except OSError:
        pytest.skip("Symbolic links are unavailable for this test account.")
    monkeypatch.setenv("TEST_PRIVATE_KEY_FILE", str(link_path))
    with pytest.raises(ImproperlyConfigured, match="nonsymlink"):
        required_private_key_file("TEST_PRIVATE_KEY")
