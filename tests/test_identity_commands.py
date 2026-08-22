from io import StringIO
from unittest.mock import patch

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from audit.models import AuditEvent
from households.models import Household, HouseholdMembership
from identity.models import MfaCredential, RecoveryCode, User
from identity.services.mfa import (
    begin_enrollment,
    confirm_enrollment,
    confirm_recovery_codes_saved,
    totp_code,
)

FIRST_PASSWORD = "first-correct-horse-battery"  # pragma: allowlist secret
SECOND_PASSWORD = "second-sunlit-river-passphrase"  # pragma: allowlist secret


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
