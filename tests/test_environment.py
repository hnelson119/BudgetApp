from pathlib import Path

import pytest
from django.core.exceptions import ImproperlyConfigured

from config.settings.environment import required_environment, required_secret_file


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
