import re
import time

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.test import Client
from django.urls import reverse

from audit.models import AuditEvent
from households.models import Household, HouseholdMembership
from identity.models import LoginThrottle, MfaCredential, RecoveryCode
from identity.services.mfa import (
    begin_enrollment,
    confirm_enrollment,
    confirm_recovery_codes_saved,
    decrypt_secret,
    mfa_is_ready,
    totp_code,
    verify_and_consume_recovery_code,
    verify_and_consume_totp,
)
from identity.services.sessions import (
    SESSION_AUTH_VERIFIED_AT,
    SESSION_PENDING_MFA_STARTED_AT,
    recent_authentication_is_valid,
)

TEST_PASSWORD = "correct-horse-battery-test"  # pragma: allowlist secret


@pytest.fixture
def mfa_household_user(db):  # type: ignore[no-untyped-def]
    household = Household.objects.create(name="MFA Household")
    user = get_user_model().objects.create_user(
        email="mfa@example.com",
        password=TEST_PASSWORD,
        display_name="MFA Person",
    )
    HouseholdMembership.objects.create(household=household, user=user)
    return household, user


def _password_login(client: Client, *, next_url: str = ""):
    data = {"username": "mfa@example.com", "password": TEST_PASSWORD}
    if next_url:
        data["next"] = next_url
    return client.post(reverse("identity:login"), data)


def _enroll_user(user):  # type: ignore[no-untyped-def]
    enrollment = begin_enrollment(user)
    confirmed = confirm_enrollment(user, totp_code(enrollment.secret))
    assert confirmed is not None
    assert confirm_recovery_codes_saved(user) is True
    user.refresh_from_db()
    return enrollment.secret, confirmed.recovery_codes


def test_totp_matches_rfc_6238_sha1_compatibility_vector(settings) -> None:  # type: ignore[no-untyped-def]
    settings.MFA_TOTP_PERIOD_SECONDS = 30
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # pragma: allowlist secret

    assert totp_code(secret, timestamp=59) == "287082"


@pytest.mark.django_db
def test_totp_seed_is_encrypted_and_bound_to_its_user(mfa_household_user) -> None:  # type: ignore[no-untyped-def]
    _, user = mfa_household_user
    enrollment = begin_enrollment(user)

    assert enrollment.secret not in enrollment.credential.encrypted_secret
    assert decrypt_secret(enrollment.credential) == enrollment.secret

    other_user = get_user_model().objects.create_user(
        email="other-mfa@example.com",
        password=TEST_PASSWORD,
    )
    other_credential = MfaCredential.objects.create(
        user=other_user,
        encrypted_secret=enrollment.credential.encrypted_secret,
    )
    with pytest.raises(ImproperlyConfigured, match="invalid"):
        decrypt_secret(other_credential)


@pytest.mark.django_db
def test_mfa_services_reject_incomplete_replayed_and_malformed_credentials(
    mfa_household_user,
) -> None:  # type: ignore[no-untyped-def]
    _, user = mfa_household_user
    assert confirm_enrollment(user, "000000") is None
    assert confirm_recovery_codes_saved(user) is False
    assert verify_and_consume_totp(user, "000000") is False
    assert verify_and_consume_recovery_code(user, "not-a-recovery-code") is False

    enrollment = begin_enrollment(user)
    assert confirm_enrollment(user, "invalid") is None
    confirmed = confirm_enrollment(user, totp_code(enrollment.secret))
    assert confirmed is not None
    assert confirm_enrollment(user, totp_code(enrollment.secret)) is None

    RecoveryCode.objects.filter(user=user).delete()
    assert confirm_recovery_codes_saved(user) is False
    assert verify_and_consume_recovery_code(user, "not-a-recovery-code") is False


@pytest.mark.django_db
def test_enrollment_requires_recovery_confirmation_before_household_access(
    client: Client,
    mfa_household_user,
) -> None:  # type: ignore[no-untyped-def]
    household, user = mfa_household_user
    login_response = _password_login(client)
    enrollment_response = client.get(reverse("identity:mfa-enroll"))
    credential = MfaCredential.objects.get(user=user)
    secret = decrypt_secret(credential)

    assert login_response.url == reverse("identity:mfa-enroll")
    assert enrollment_response.status_code == 200
    assert b"data:image/svg+xml;base64," in enrollment_response.content
    assert secret.encode() in enrollment_response.content
    assert secret not in credential.encrypted_secret

    recovery_response = client.post(
        reverse("identity:mfa-enroll"),
        {"code": totp_code(secret)},
    )
    displayed_codes = [
        code.decode()
        for code in re.findall(rb"<code>([A-Z0-9-]+)</code>", recovery_response.content)
    ]

    assert recovery_response.status_code == 200
    assert len(displayed_codes) == settings.MFA_RECOVERY_CODE_COUNT
    assert RecoveryCode.objects.filter(user=user).count() == settings.MFA_RECOVERY_CODE_COUNT
    assert all(
        code.replace("-", "")[8:] not in stored.code_hash
        for code, stored in zip(
            displayed_codes, RecoveryCode.objects.filter(user=user), strict=True
        )
    )
    restricted_response = client.get(reverse("core:home"))
    assert restricted_response.url == reverse("identity:mfa-recovery-confirm")

    confirmation_response = client.post(
        reverse("identity:mfa-recovery-confirm"),
        {"saved": "on"},
    )
    user.refresh_from_db()
    assert confirmation_response.url == reverse("core:home")
    assert mfa_is_ready(user) is True
    assert client.get(reverse("core:home")).status_code == 200
    assert AuditEvent.objects.filter(household=household, action="auth.mfa_enrolled").exists()
    assert AuditEvent.objects.filter(
        household=household,
        action="auth.recovery_codes_confirmed",
    ).exists()


@pytest.mark.django_db
def test_enrolled_login_requires_mfa_and_recovery_code_is_single_use(
    client: Client,
    mfa_household_user,
) -> None:  # type: ignore[no-untyped-def]
    _, user = mfa_household_user
    _, recovery_codes = _enroll_user(user)

    password_response = _password_login(client, next_url="/")
    assert password_response.status_code == 302
    assert password_response.url.startswith(reverse("identity:mfa-verify"))
    assert "_auth_user_id" not in client.session

    verify_response = client.post(
        reverse("identity:mfa-verify"),
        {"code": recovery_codes[0], "next": "/"},
    )
    assert verify_response.url == reverse("core:home")
    assert "_auth_user_id" in client.session
    used_code = RecoveryCode.objects.get(identifier=recovery_codes[0][:8])
    assert used_code.used_at is not None
    event = AuditEvent.objects.get(action="auth.login_succeeded")
    assert event.after_payload == {"authentication_method": "password_recovery_code"}

    client.post(reverse("identity:logout"))
    _password_login(client)
    replay_response = client.post(
        reverse("identity:mfa-verify"),
        {"code": recovery_codes[0]},
    )
    assert replay_response.status_code == 200
    assert b"verification code was not accepted" in replay_response.content
    assert "_auth_user_id" not in client.session


@pytest.mark.django_db
def test_password_alone_cannot_restart_a_partially_confirmed_enrollment(
    client: Client,
    mfa_household_user,
) -> None:  # type: ignore[no-untyped-def]
    _, user = mfa_household_user
    enrollment = begin_enrollment(user)
    confirmed = confirm_enrollment(user, totp_code(enrollment.secret))
    assert confirmed is not None

    login_response = _password_login(client)
    restart_response = client.post(reverse("identity:mfa-enrollment-restart"))

    assert login_response.url.startswith(reverse("identity:mfa-verify"))
    assert restart_response.url.startswith(reverse("identity:login"))
    assert MfaCredential.objects.filter(user=user, confirmed_at__isnull=False).exists()


@pytest.mark.django_db
def test_totp_cannot_be_replayed(mfa_household_user, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    _, user = mfa_household_user
    base_time = 1_700_000_000
    monkeypatch.setattr("identity.services.mfa.time.time", lambda: base_time)
    secret, _ = _enroll_user(user)
    credential = MfaCredential.objects.get(user=user)
    credential.last_used_step = None
    credential.save(update_fields=("last_used_step",))
    code = totp_code(secret)

    from identity.services.mfa import verify_and_consume_totp

    assert verify_and_consume_totp(user, code) is True
    assert verify_and_consume_totp(user, code) is False


@pytest.mark.django_db
def test_pending_mfa_expires_without_consuming_recovery_code(
    client: Client,
    mfa_household_user,
) -> None:  # type: ignore[no-untyped-def]
    _, user = mfa_household_user
    _, recovery_codes = _enroll_user(user)
    _password_login(client)
    session = client.session
    session[SESSION_PENDING_MFA_STARTED_AT] = (
        int(time.time()) - settings.MFA_PENDING_TIMEOUT_SECONDS - 1
    )
    session.save()

    response = client.post(reverse("identity:mfa-verify"), {"code": recovery_codes[0]})

    assert response.url == reverse("identity:login")
    assert RecoveryCode.objects.get(identifier=recovery_codes[0][:8]).used_at is None


@pytest.mark.django_db
def test_mfa_failures_are_rate_limited_and_audited(
    client: Client,
    mfa_household_user,
) -> None:  # type: ignore[no-untyped-def]
    household, user = mfa_household_user
    _, recovery_codes = _enroll_user(user)
    _password_login(client)

    responses = [
        client.post(reverse("identity:mfa-verify"), {"code": "000000"})
        for _ in range(settings.LOGIN_RATE_LIMIT_FAILURES)
    ]
    blocked_valid_response = client.post(
        reverse("identity:mfa-verify"),
        {"code": recovery_codes[0]},
    )

    assert all(response.status_code == 200 for response in responses[:-1])
    assert responses[-1].status_code == 429
    assert blocked_valid_response.status_code == 429
    assert "_auth_user_id" not in client.session
    assert RecoveryCode.objects.get(identifier=recovery_codes[0][:8]).used_at is None
    assert LoginThrottle.objects.count() == 2
    assert AuditEvent.objects.filter(household=household, action="auth.mfa_failed").count() == 6


@pytest.mark.django_db
def test_mfa_verification_requires_csrf(mfa_household_user) -> None:  # type: ignore[no-untyped-def]
    _, user = mfa_household_user
    _, recovery_codes = _enroll_user(user)
    client = Client(enforce_csrf_checks=True)
    client.get(reverse("identity:login"))

    response = client.post(reverse("identity:mfa-verify"), {"code": recovery_codes[0]})

    assert response.status_code == 403
    assert RecoveryCode.objects.get(identifier=recovery_codes[0][:8]).used_at is None


@pytest.mark.django_db
def test_sensitive_reauthentication_requires_password_and_second_factor(
    client: Client,
    mfa_household_user,
) -> None:  # type: ignore[no-untyped-def]
    household, user = mfa_household_user
    _, recovery_codes = _enroll_user(user)
    _password_login(client)
    client.post(reverse("identity:mfa-verify"), {"code": recovery_codes[0]})
    session = client.session
    session[SESSION_AUTH_VERIFIED_AT] = int(time.time()) - settings.RECENT_AUTH_TIMEOUT_SECONDS - 1
    session.save()

    get_response = client.get(reverse("identity:reauthenticate"))
    assert get_response.status_code == 200
    assert "no-store" in get_response.headers["Cache-Control"]

    failed_response = client.post(
        reverse("identity:reauthenticate"),
        {"password": "wrong-password", "code": recovery_codes[1]},  # pragma: allowlist secret
    )
    assert failed_response.status_code == 200
    assert RecoveryCode.objects.get(identifier=recovery_codes[1][:8]).used_at is None

    success_response = client.post(
        reverse("identity:reauthenticate"),
        {"password": TEST_PASSWORD, "code": recovery_codes[1], "next": "/"},
    )
    request = success_response.wsgi_request
    assert success_response.url == reverse("core:home")
    assert recent_authentication_is_valid(request) is True
    assert RecoveryCode.objects.get(identifier=recovery_codes[1][:8]).used_at is not None
    assert AuditEvent.objects.filter(
        household=household,
        action="auth.reauthentication_failed",
    ).exists()
    assert AuditEvent.objects.filter(
        household=household,
        action="auth.reauthentication_succeeded",
    ).exists()
