from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings

from households.models import Household, HouseholdMembership
from identity.forms import ForgottenPasswordRecoveryForm, SecurePasswordChangeForm
from identity.models import User
from identity.password_validation import (
    CORPUS_MAGIC,
    ContextSpecificPasswordValidator,
    OfflineBreachedPasswordValidator,
    clear_breached_password_corpus_cache,
    load_breached_password_corpus,
    validate_breached_password_corpus,
)

BREACHED_PASSWORD = "breached-corpus-password"  # pragma: allowlist secret
SAFE_PASSWORD = "violet-river-cello-starlight"  # pragma: allowlist secret
CURRENT_PASSWORD = "current-amber-harbor-passphrase"  # pragma: allowlist secret
BASELINE_BREACHED_PASSWORD = "password"  # pragma: allowlist secret


def _digest(password: str) -> bytes:
    return (
        hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper().encode()
    )


def _metadata(*, entries: int, payload: bytes) -> dict[str, object]:
    today = date.today().isoformat()
    return {
        "corpus_version": 1,
        "entries": entries,
        "generated_at": today,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "selection": "test-only-selection",
        "source_name": "Test fixture",
        "source_retrieved_at": today,
        "source_sha256": "a" * 64,
        "source_url": "https://example.test/password-source.txt",
    }


def _corpus_bytes(
    digests: list[bytes],
    *,
    metadata_updates: dict[str, object] | None = None,
) -> bytes:
    payload = b"".join(digest + b"\n" for digest in digests)
    metadata = _metadata(entries=len(digests), payload=payload)
    if metadata_updates:
        metadata.update(metadata_updates)
    record = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
    return CORPUS_MAGIC + record + b"\n" + payload


def _write_corpus(path: Path, passwords: list[str]) -> Path:
    digests = sorted({_digest(password) for password in passwords})
    path.write_bytes(_corpus_bytes(digests))
    clear_breached_password_corpus_cache()
    return path


def _load(path: Path, *, minimum_entries: int = 1, maximum_bytes: int = 4096):  # type: ignore[no-untyped-def]
    clear_breached_password_corpus_cache()
    return load_breached_password_corpus(
        path,
        minimum_entries=minimum_entries,
        maximum_age_days=180,
        maximum_bytes=maximum_bytes,
    )


@pytest.mark.parametrize(
    "password",
    [
        "BudgetApp",
        "my-budget-app2026",
        "Budg3t@pp42",
        "our household budget admin 7",
        "household-budge7",
        "the_paycheck-budget_password99",
    ],
)
def test_context_specific_validator_rejects_documented_name_permutations(password: str) -> None:
    validator = ContextSpecificPasswordValidator(
        identifiers=("BudgetApp", "Household Budget", "Paycheck Budget")
    )

    with pytest.raises(ValidationError) as raised:
        validator.validate(password)

    assert raised.value.code == "password_context_specific"
    assert password not in str(raised.value)


def test_context_specific_validator_allows_unrelated_passphrase() -> None:
    ContextSpecificPasswordValidator(identifiers=("BudgetApp",)).validate(SAFE_PASSWORD)


@pytest.mark.parametrize("identifiers", [(), [], "BudgetApp", 7, ("BudgetApp", 7)])
def test_context_specific_validator_rejects_invalid_configuration(
    identifiers: object,
) -> None:
    with pytest.raises(ImproperlyConfigured, match="non-empty strings"):
        ContextSpecificPasswordValidator(identifiers=identifiers)  # type: ignore[arg-type]


def test_offline_validator_blocks_local_match_without_network_or_logging(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    corpus_path = _write_corpus(tmp_path / "corpus.txt", [BREACHED_PASSWORD])
    validator = OfflineBreachedPasswordValidator(
        corpus_path=corpus_path,
        minimum_entries=1,
        maximum_age_days=180,
        maximum_bytes=4096,
    )
    candidate_digest = _digest(BREACHED_PASSWORD).decode()

    caplog.set_level(logging.DEBUG)
    with (
        patch.object(socket, "create_connection", side_effect=AssertionError("network used")),
        pytest.raises(ValidationError) as raised,
    ):
        validator.validate(BREACHED_PASSWORD)

    assert raised.value.code == "password_breached"
    assert BREACHED_PASSWORD not in caplog.text
    assert candidate_digest not in caplog.text
    assert BREACHED_PASSWORD not in str(raised.value)
    validator.validate(SAFE_PASSWORD)


def test_packaged_corpus_blocks_known_baseline_value() -> None:
    validator = OfflineBreachedPasswordValidator()

    with pytest.raises(ValidationError, match="data breach"):
        validator.validate(BASELINE_BREACHED_PASSWORD)
    validator.validate(SAFE_PASSWORD)

    attributes = (Path(__file__).resolve().parents[1] / ".gitattributes").read_text(
        encoding="utf-8"
    )
    assert "identity/data/breached-passwords-*.txt text eol=lf" in attributes


def test_django_password_validation_and_user_facing_forms_use_custom_policy(tmp_path: Path) -> None:
    corpus_path = _write_corpus(tmp_path / "corpus.txt", [BREACHED_PASSWORD])
    validator_settings = [
        {"NAME": "identity.password_validation.ContextSpecificPasswordValidator"},
        {"NAME": "identity.password_validation.OfflineBreachedPasswordValidator"},
    ]

    with override_settings(
        AUTH_PASSWORD_VALIDATORS=validator_settings,
        PASSWORD_CONTEXT_IDENTIFIERS=("BudgetApp",),
        BREACHED_PASSWORD_CORPUS_PATH=corpus_path,
        BREACHED_PASSWORD_CORPUS_MINIMUM_ENTRIES=1,
        BREACHED_PASSWORD_CORPUS_MAXIMUM_AGE_DAYS=180,
        BREACHED_PASSWORD_CORPUS_MAXIMUM_BYTES=4096,
    ):
        with pytest.raises(ValidationError, match="data breach"):
            validate_password(BREACHED_PASSWORD)
        with pytest.raises(ValidationError, match="application name"):
            validate_password("my-budget-app2026")

        recovery_form = ForgottenPasswordRecoveryForm(
            data={
                "email": "person@example.com",
                "code": "ABCDEF123456",  # pragma: allowlist secret
                "new_password1": BREACHED_PASSWORD,
                "new_password2": BREACHED_PASSWORD,
            }
        )
        assert recovery_form.is_valid() is False
        assert "data breach" in recovery_form.errors["new_password1"][0]

        user = User(email="person@example.com")
        user.set_password(CURRENT_PASSWORD)
        change_form = SecurePasswordChangeForm(
            user=user,
            data={
                "old_password": CURRENT_PASSWORD,
                "new_password1": BREACHED_PASSWORD,
                "new_password2": BREACHED_PASSWORD,
            },
        )
        assert change_form.is_valid() is False
        assert "data breach" in change_form.errors["new_password2"][0]


@pytest.mark.django_db
def test_console_provisioning_uses_custom_password_policy(tmp_path: Path) -> None:
    corpus_path = _write_corpus(tmp_path / "corpus.txt", [BREACHED_PASSWORD])

    with (
        override_settings(
            AUTH_PASSWORD_VALIDATORS=[
                {"NAME": "identity.password_validation.OfflineBreachedPasswordValidator"}
            ],
            BREACHED_PASSWORD_CORPUS_PATH=corpus_path,
            BREACHED_PASSWORD_CORPUS_MINIMUM_ENTRIES=1,
            BREACHED_PASSWORD_CORPUS_MAXIMUM_AGE_DAYS=180,
            BREACHED_PASSWORD_CORPUS_MAXIMUM_BYTES=4096,
        ),
        patch(
            "identity.management.commands.bootstrap_household.getpass.getpass",
            side_effect=[BREACHED_PASSWORD, BREACHED_PASSWORD],
        ),
        pytest.raises(CommandError, match="data breach"),
    ):
        call_command(
            "bootstrap_household",
            "--household-name",
            "Policy Test",
            "--user-email",
            "first@example.com",
            "--user-email",
            "second@example.com",
            "--display-name",
            "First",
            "--display-name",
            "Second",
        )


@pytest.mark.django_db
def test_console_password_reset_uses_custom_password_policy(tmp_path: Path) -> None:
    corpus_path = _write_corpus(tmp_path / "corpus.txt", [BREACHED_PASSWORD])
    household = Household.objects.create(name="Reset Policy Test")
    user = User.objects.create_user(email="reset@example.com", password=CURRENT_PASSWORD)
    HouseholdMembership.objects.create(household=household, user=user)

    with (
        override_settings(
            AUTH_PASSWORD_VALIDATORS=[
                {"NAME": "identity.password_validation.OfflineBreachedPasswordValidator"}
            ],
            BREACHED_PASSWORD_CORPUS_PATH=corpus_path,
            BREACHED_PASSWORD_CORPUS_MINIMUM_ENTRIES=1,
            BREACHED_PASSWORD_CORPUS_MAXIMUM_AGE_DAYS=180,
            BREACHED_PASSWORD_CORPUS_MAXIMUM_BYTES=4096,
        ),
        patch(
            "identity.management.commands.reset_user_password.getpass.getpass",
            side_effect=[BREACHED_PASSWORD, BREACHED_PASSWORD],
        ),
        pytest.raises(CommandError, match="did not meet policy"),
    ):
        call_command(
            "reset_user_password",
            user.email,
            reason="Password policy test",
        )

    user.refresh_from_db()
    assert user.check_password(CURRENT_PASSWORD)


def test_corpus_loader_validates_and_binary_searches_sorted_hashes(tmp_path: Path) -> None:
    corpus_path = _write_corpus(tmp_path / "corpus.txt", [SAFE_PASSWORD, BREACHED_PASSWORD])

    corpus = _load(corpus_path, minimum_entries=2)

    assert corpus.metadata["entries"] == 2
    assert corpus.contains(_digest(BREACHED_PASSWORD)) is True
    assert corpus.contains(_digest("not-in-corpus")) is False


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        (b"wrong-header\n{}\n", "header is invalid"),
        (CORPUS_MAGIC + b"not-json\n", "not valid JSON"),
        (
            CORPUS_MAGIC + b'{"corpus_version":1,"corpus_version":1}\n',
            "not valid JSON",
        ),
        (_corpus_bytes([_digest(BREACHED_PASSWORD)])[:-1], "entry count"),
        (
            _corpus_bytes(
                [_digest(BREACHED_PASSWORD)],
                metadata_updates={"payload_sha256": "0" * 64},
            ),
            "integrity check",
        ),
        (
            _corpus_bytes(
                [_digest(BREACHED_PASSWORD)],
                metadata_updates={"source_url": "http://example.test/source"},
            ),
            "must use HTTPS",
        ),
        (
            _corpus_bytes(
                [_digest(BREACHED_PASSWORD)],
                metadata_updates={"corpus_version": True},
            ),
            "version is unsupported",
        ),
    ],
)
def test_corpus_loader_fails_closed_for_corrupt_content(
    tmp_path: Path,
    contents: bytes,
    message: str,
) -> None:
    corpus_path = tmp_path / "corrupt.txt"
    corpus_path.write_bytes(contents)

    with pytest.raises(ImproperlyConfigured, match=message):
        _load(corpus_path)


@pytest.mark.parametrize("arrangement", ["duplicate", "unsorted", "lowercase", "bad-delimiter"])
def test_corpus_loader_rejects_noncanonical_hash_records(
    tmp_path: Path,
    arrangement: str,
) -> None:
    first, second = sorted((_digest(BREACHED_PASSWORD), _digest(SAFE_PASSWORD)))
    if arrangement == "duplicate":
        payload = first + b"\n" + first + b"\n"
    elif arrangement == "unsorted":
        payload = second + b"\n" + first + b"\n"
    elif arrangement == "lowercase":
        payload = first.lower() + b"\n"
    else:
        payload = first + b" "
    metadata = _metadata(entries=payload.count(b"\n") or 1, payload=payload)
    record = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
    corpus_path = tmp_path / f"{arrangement}.txt"
    corpus_path.write_bytes(CORPUS_MAGIC + record + b"\n" + payload)

    with pytest.raises(ImproperlyConfigured, match=r"delimiter|uppercase, unique, and sorted"):
        _load(corpus_path)


@pytest.mark.parametrize(
    ("retrieved_at", "generated_at", "message"),
    [
        (date.today() - timedelta(days=181), date.today(), "is stale"),
        (date.today() + timedelta(days=1), date.today() + timedelta(days=1), "future"),
        (date.today(), date.today() - timedelta(days=1), "generation date"),
    ],
)
def test_corpus_loader_rejects_stale_or_impossible_dates(
    tmp_path: Path,
    retrieved_at: date,
    generated_at: date,
    message: str,
) -> None:
    corpus_path = tmp_path / "dated.txt"
    corpus_path.write_bytes(
        _corpus_bytes(
            [_digest(BREACHED_PASSWORD)],
            metadata_updates={
                "source_retrieved_at": retrieved_at.isoformat(),
                "generated_at": generated_at.isoformat(),
            },
        )
    )

    with pytest.raises(ImproperlyConfigured, match=message):
        _load(corpus_path)


def test_corpus_loader_rejects_missing_oversized_and_invalid_limits(tmp_path: Path) -> None:
    corpus_path = _write_corpus(tmp_path / "corpus.txt", [BREACHED_PASSWORD])

    with pytest.raises(ImproperlyConfigured, match="Unable to read"):
        _load(tmp_path / "missing.txt")
    with pytest.raises(ImproperlyConfigured, match="size limit"):
        _load(corpus_path, maximum_bytes=16)
    with pytest.raises(ImproperlyConfigured, match="positive integers"):
        load_breached_password_corpus(
            corpus_path,
            minimum_entries=True,
            maximum_age_days=180,
            maximum_bytes=4096,
        )


def test_explicit_settings_validation_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(ImproperlyConfigured, match="Unable to read"):
        validate_breached_password_corpus(
            tmp_path / "missing.txt",
            minimum_entries=1,
            maximum_age_days=180,
            maximum_bytes=4096,
        )


def test_corpus_loader_rejects_symlink(tmp_path: Path) -> None:
    target = _write_corpus(tmp_path / "target.txt", [BREACHED_PASSWORD])
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Symlink creation is unavailable on this host.")

    with pytest.raises(ImproperlyConfigured, match="non-symlink"):
        _load(link)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits are required")
def test_corpus_loader_rejects_group_writable_file(tmp_path: Path) -> None:
    corpus_path = _write_corpus(tmp_path / "corpus.txt", [BREACHED_PASSWORD])
    corpus_path.chmod(0o664)

    with pytest.raises(ImproperlyConfigured, match="group or other"):
        _load(corpus_path)


def _run_builder(
    source: Path,
    output: Path,
    *,
    input_format: str,
    maximum_entries: int,
    minimum_entries: int,
    expected_sha256: str | None = None,
    replace: bool = False,
    source_name: str = "Test source",
) -> None:
    arguments = [
        str(source),
        str(output),
        "--input-format",
        input_format,
        "--expected-sha256",
        expected_sha256 or hashlib.sha256(source.read_bytes()).hexdigest(),
        "--source-name",
        source_name,
        "--source-url",
        "https://example.test/source.txt",
        "--source-retrieved-at",
        date.today().isoformat(),
        "--max-entries",
        str(maximum_entries),
        "--minimum-entries",
        str(minimum_entries),
    ]
    if replace:
        arguments.append("--replace")
    call_command("build_breached_password_corpus", *arguments)


def test_plaintext_builder_hashes_unicode_and_emits_no_plaintext(tmp_path: Path) -> None:
    source = tmp_path / "plaintext.txt"
    output = tmp_path / "corpus.txt"
    passwords = ["ordinary-password", "café-passphrase"]  # pragma: allowlist secret
    source.write_text("\n".join(passwords) + "\n", encoding="utf-8")

    _run_builder(
        source,
        output,
        input_format="plaintext",
        maximum_entries=2,
        minimum_entries=2,
    )

    corpus = _load(output, minimum_entries=2)
    assert all(corpus.contains(_digest(password)) for password in passwords)
    output_bytes = output.read_bytes()
    assert all(password.encode() not in output_bytes for password in passwords)


def test_hibp_builder_selects_highest_counts_with_deterministic_ties(tmp_path: Path) -> None:
    source = tmp_path / "hibp.txt"
    output = tmp_path / "corpus.txt"
    first = b"A" * 40
    tied_out = b"B" * 40
    highest = b"C" * 40
    source.write_bytes(first + b":5\n" + tied_out + b":5\n" + highest + b":9\n")

    _run_builder(
        source,
        output,
        input_format="hibp-sha1",
        maximum_entries=2,
        minimum_entries=2,
    )

    corpus = _load(output, minimum_entries=2)
    assert corpus.contains(first) is True
    assert corpus.contains(highest) is True
    assert corpus.contains(tied_out) is False


@pytest.mark.parametrize(
    "record",
    [
        b"a" * 40 + b":1\n",
        b"A" * 40 + b":0\n",
        b"A" * 40 + b":1x\n",
        b"A" * 40 + b":1:2\n",
        b"not-a-record\n",
    ],
)
def test_hibp_builder_rejects_malformed_records(tmp_path: Path, record: bytes) -> None:
    source = tmp_path / "hibp.txt"
    output = tmp_path / "corpus.txt"
    source.write_bytes(record)

    with pytest.raises(CommandError, match=r"HASH:COUNT|invalid hash or count"):
        _run_builder(
            source,
            output,
            input_format="hibp-sha1",
            maximum_entries=1,
            minimum_entries=1,
        )

    assert output.exists() is False


def test_builder_digest_mismatch_and_replace_guards_preserve_existing_output(
    tmp_path: Path,
) -> None:
    source = tmp_path / "plaintext.txt"
    output = tmp_path / "corpus.txt"
    source.write_text("candidate\n", encoding="utf-8")
    output.write_bytes(b"existing-corpus")

    with pytest.raises(CommandError, match="already exists"):
        _run_builder(
            source,
            output,
            input_format="plaintext",
            maximum_entries=1,
            minimum_entries=1,
        )
    with pytest.raises(CommandError, match="did not match"):
        _run_builder(
            source,
            output,
            input_format="plaintext",
            maximum_entries=1,
            minimum_entries=1,
            expected_sha256="0" * 64,
            replace=True,
        )

    assert output.read_bytes() == b"existing-corpus"


def test_builder_atomic_install_failure_leaves_no_partial_output(tmp_path: Path) -> None:
    source = tmp_path / "plaintext.txt"
    output = tmp_path / "corpus.txt"
    source.write_text("candidate\n", encoding="utf-8")

    with (
        patch(
            "identity.management.commands.build_breached_password_corpus.os.replace",
            side_effect=OSError("replace failed"),
        ),
        pytest.raises(CommandError, match="atomically"),
    ):
        _run_builder(
            source,
            output,
            input_format="plaintext",
            maximum_entries=1,
            minimum_entries=1,
        )

    assert output.exists() is False
    assert list(tmp_path.glob(f".{output.name}.*")) == []


def test_builder_rejects_unsafe_input_and_metadata(tmp_path: Path) -> None:
    source = tmp_path / "plaintext.txt"
    source.write_text("candidate\n", encoding="utf-8")
    link = tmp_path / "source-link.txt"
    try:
        link.symlink_to(source)
    except OSError:
        link = None

    if link is not None:
        with pytest.raises(CommandError, match="non-symlink"):
            _run_builder(
                link,
                tmp_path / "symlink-output.txt",
                input_format="plaintext",
                maximum_entries=1,
                minimum_entries=1,
            )

    with pytest.raises(CommandError, match="source-name"):
        _run_builder(
            source,
            tmp_path / "metadata-output.txt",
            input_format="plaintext",
            maximum_entries=1,
            minimum_entries=1,
            source_name="x" * 5000,
        )


def test_builder_rejects_oversized_source_line_before_writing(tmp_path: Path) -> None:
    source = tmp_path / "plaintext.txt"
    output = tmp_path / "corpus.txt"
    source.write_bytes(b"x" * 4097 + b"\n")

    with pytest.raises(CommandError, match="safe length limit"):
        _run_builder(
            source,
            output,
            input_format="plaintext",
            maximum_entries=1,
            minimum_entries=1,
        )

    assert output.exists() is False
