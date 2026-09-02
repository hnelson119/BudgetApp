from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings

from audit.models import AuditEvent
from households.models import Household, HouseholdMembership
from identity.models import MfaCredential, RecoveryCode, User
from identity.services.mfa import (
    begin_enrollment,
    confirm_enrollment,
    confirm_recovery_codes_saved,
    decrypt_secret,
    totp_code,
)

FIRST_PASSWORD = "first-correct-horse-battery"  # pragma: allowlist secret
SECOND_PASSWORD = "second-sunlit-river-passphrase"  # pragma: allowlist secret
ROTATED_MFA_KEY = (
    "rotated-mfa-key-material-for-tests-only-0123456789ABCDEF"  # pragma: allowlist secret
)


@pytest.mark.django_db
def test_bootstrap_creates_exactly_two_distinct_users_without_cli_passwords() -> None:
    output = StringIO()
    with patch(
        "identity.management.commands.bootstrap_household.getpass.getpass",
        side_effect=[
            FIRST_PASSWORD,
            FIRST_PASSWORD,
            SECOND_PASSWORD,
            SECOND_PASSWORD,
        ],
    ):
        call_command(
            "bootstrap_household",
            "--household-name",
            "Our Household",
            "--user-email",
            "First@Example.com",
            "--user-email",
            "second@example.com",
            "--display-name",
            "First",
            "--display-name",
            "Second",
            stdout=output,
        )

    household = Household.objects.get()
    users = list(User.objects.order_by("email"))
    assert household.name == "Our Household"
    assert [user.email for user in users] == ["first@example.com", "second@example.com"]
    assert users[0].check_password(FIRST_PASSWORD)
    assert users[1].check_password(SECOND_PASSWORD)
    assert HouseholdMembership.objects.filter(household=household).count() == 2
    event = AuditEvent.objects.get(action="household.bootstrap_completed")
    assert event.actor is None
    assert event.after_payload == {"member_count": 2, "mfa_enrollment_required": True}
    assert "must enroll MFA" in output.getvalue()


@pytest.mark.django_db
def test_bootstrap_rejects_a_shared_password() -> None:
    with (
        patch(
            "identity.management.commands.bootstrap_household.getpass.getpass",
            side_effect=[FIRST_PASSWORD] * 4,
        ),
        pytest.raises(CommandError, match="must not share"),
    ):
        call_command(
            "bootstrap_household",
            "--household-name",
            "Our Household",
            "--user-email",
            "first@example.com",
            "--user-email",
            "second@example.com",
            "--display-name",
            "First",
            "--display-name",
            "Second",
        )

    assert Household.objects.count() == 0
    assert User.objects.count() == 0


@pytest.mark.django_db
def test_emergency_mfa_reset_revokes_sessions_codes_and_seed() -> None:
    household = Household.objects.create(name="Recovery Household")
    user = User.objects.create_user(email="recover@example.com", password=FIRST_PASSWORD)
    HouseholdMembership.objects.create(household=household, user=user)
    enrollment = begin_enrollment(user)
    confirmed = confirm_enrollment(user, totp_code(enrollment.secret))
    assert confirmed is not None
    assert confirm_recovery_codes_saved(user) is True
    user.refresh_from_db()
    previous_version = user.session_version
    output = StringIO()

    with patch("builtins.input", return_value=user.email):
        call_command(
            "reset_user_mfa",
            user.email,
            reason="Authenticator was permanently lost",
            stdout=output,
        )

    user.refresh_from_db()
    assert user.mfa_enrolled_at is None
    assert user.session_version == previous_version + 1
    assert MfaCredential.objects.filter(user=user).count() == 0
    assert RecoveryCode.objects.filter(user=user).count() == 0
    event = AuditEvent.objects.get(action="auth.mfa_emergency_reset")
    assert event.reason == "Authenticator was permanently lost"
    assert event.actor is None
    assert "sessions are revoked" in output.getvalue()


@pytest.mark.django_db
def test_emergency_password_reset_changes_password_revokes_sessions_and_audits() -> None:
    household = Household.objects.create(name="Password Recovery Household")
    user = User.objects.create_user(email="password-recover@example.com", password=FIRST_PASSWORD)
    HouseholdMembership.objects.create(household=household, user=user)
    previous_version = user.session_version
    output = StringIO()

    with patch(
        "identity.management.commands.reset_user_password.getpass.getpass",
        side_effect=[SECOND_PASSWORD, SECOND_PASSWORD],
    ):
        call_command(
            "reset_user_password",
            user.email,
            reason="Password manager device was lost",
            stdout=output,
        )

    user.refresh_from_db()
    assert user.check_password(SECOND_PASSWORD)
    assert not user.check_password(FIRST_PASSWORD)
    assert user.session_version == previous_version + 1
    event = AuditEvent.objects.get(action="auth.password_emergency_reset")
    assert event.actor is None
    assert event.reason == "Password manager device was lost"
    assert event.after_payload == {
        "credential_changed": True,
        "session_version": previous_version + 1,
    }
    assert SECOND_PASSWORD not in output.getvalue()
    assert "sessions are revoked" in output.getvalue()


@pytest.mark.django_db
def test_emergency_password_reset_rejects_reuse_and_mismatch() -> None:
    household = Household.objects.create(name="Password Refusal Household")
    user = User.objects.create_user(email="password-refuse@example.com", password=FIRST_PASSWORD)
    HouseholdMembership.objects.create(household=household, user=user)

    for prompts, message in (
        ((SECOND_PASSWORD, FIRST_PASSWORD), "confirmation did not match"),
        ((FIRST_PASSWORD, FIRST_PASSWORD), "must be different"),
    ):
        with (
            patch(
                "identity.management.commands.reset_user_password.getpass.getpass",
                side_effect=prompts,
            ),
            pytest.raises(CommandError, match=message),
        ):
            call_command(
                "reset_user_password",
                user.email,
                reason="Disposable refusal proof",
            )

    user.refresh_from_db()
    assert user.check_password(FIRST_PASSWORD)
    assert not AuditEvent.objects.filter(action="auth.password_emergency_reset").exists()


@pytest.mark.django_db
def test_mfa_encryption_key_command_rotates_atomically_and_audits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    household = Household.objects.create(name="Rotation Household")
    user = User.objects.create_user(email="rotate@example.com", password=FIRST_PASSWORD)
    HouseholdMembership.objects.create(household=household, user=user)
    enrollment = begin_enrollment(user)
    original_ciphertext = enrollment.credential.encrypted_secret
    original_session_version = user.session_version
    next_key_file = tmp_path / "next_mfa_key"
    next_key_file.write_text(ROTATED_MFA_KEY, encoding="utf-8")
    monkeypatch.delenv("DJANGO_MFA_ENCRYPTION_KEY_NEXT", raising=False)
    monkeypatch.setenv("DJANGO_MFA_ENCRYPTION_KEY_NEXT_FILE", str(next_key_file))
    output = StringIO()

    call_command(
        "rotate_mfa_encryption_key",
        new_version=2,
        reason="Scheduled cryptographic maintenance",
        confirm="rotate-to-v2",
        stdout=output,
    )

    credential = MfaCredential.objects.get(user=user)
    user.refresh_from_db()
    assert credential.key_version == 2
    assert credential.encrypted_secret != original_ciphertext
    assert user.session_version == original_session_version
    with pytest.raises(ImproperlyConfigured, match="cannot be decrypted"):
        decrypt_secret(credential)
    with override_settings(
        MFA_ENCRYPTION_KEY=ROTATED_MFA_KEY,
        MFA_ENCRYPTION_KEY_VERSION=2,
    ):
        assert decrypt_secret(credential) == enrollment.secret
    event = AuditEvent.objects.get(action="security.mfa_key_rotated")
    assert event.actor is None
    assert event.before_payload == {"key_version": 1}
    assert event.after_payload == {"key_version": 2}
    assert event.reason == "Scheduled cryptographic maintenance"
    assert ROTATED_MFA_KEY not in output.getvalue()
    assert "completed atomically" in output.getvalue()


@pytest.mark.django_db
def test_mfa_encryption_key_command_rolls_back_if_any_seed_is_invalid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    household = Household.objects.create(name="Rollback Household")
    first = User.objects.create_user(email="first-rotate@example.com", password=FIRST_PASSWORD)
    second = User.objects.create_user(email="second-rotate@example.com", password=SECOND_PASSWORD)
    HouseholdMembership.objects.create(household=household, user=first)
    HouseholdMembership.objects.create(household=household, user=second)
    first_credential = begin_enrollment(first).credential
    second_credential = begin_enrollment(second).credential
    original_ciphertext = first_credential.encrypted_secret
    second_credential.encrypted_secret = "corrupt-ciphertext"  # pragma: allowlist secret
    second_credential.save(update_fields=("encrypted_secret",))
    next_key_file = tmp_path / "next_mfa_key"
    next_key_file.write_text(ROTATED_MFA_KEY, encoding="utf-8")
    monkeypatch.setenv("DJANGO_MFA_ENCRYPTION_KEY_NEXT_FILE", str(next_key_file))

    with pytest.raises(CommandError, match="cannot be decrypted"):
        call_command(
            "rotate_mfa_encryption_key",
            new_version=2,
            reason="Rollback proof",
            confirm="rotate-to-v2",
        )

    first_credential.refresh_from_db()
    assert first_credential.encrypted_secret == original_ciphertext
    assert first_credential.key_version == 1
    assert not AuditEvent.objects.filter(action="security.mfa_key_rotated").exists()


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("new_version", "confirmation", "reason", "message"),
    [
        (2, "wrong", "Scheduled rotation", "Confirmation did not match"),
        (1, "rotate-to-v1", "Scheduled rotation", "must increase monotonically"),
        (2, "rotate-to-v2", "", "reason of 1 to 500"),
    ],
)
def test_mfa_encryption_key_command_refuses_unsafe_requests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    new_version: int,
    confirmation: str,
    reason: str,
    message: str,
) -> None:
    next_key_file = tmp_path / "next_mfa_key"
    next_key_file.write_text(ROTATED_MFA_KEY, encoding="utf-8")
    monkeypatch.setenv("DJANGO_MFA_ENCRYPTION_KEY_NEXT_FILE", str(next_key_file))

    with pytest.raises(CommandError, match=message):
        call_command(
            "rotate_mfa_encryption_key",
            new_version=new_version,
            reason=reason,
            confirm=confirmation,
        )
