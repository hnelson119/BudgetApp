import time
from unittest.mock import patch

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.test import Client
from django.urls import reverse

from audit.models import AuditEvent
from households.models import Household, HouseholdMembership
from identity.models import LoginThrottle, RecoveryCode
from identity.services.mfa import (
    begin_enrollment,
    confirm_enrollment,
    confirm_recovery_codes_saved,
    totp_code,
)

CURRENT_PASSWORD = "recovery-current-household-passphrase"  # pragma: allowlist secret
NEW_PASSWORD = "recovery-new-riverbank-passphrase"  # pragma: allowlist secret


@pytest.fixture
def recovery_user(db):  # type: ignore[no-untyped-def]
    household = Household.objects.create(name="Password Recovery Household")
    user = get_user_model().objects.create_user(
        email="recover@example.com",
        password=CURRENT_PASSWORD,
        display_name="Recovery Person",
    )
    HouseholdMembership.objects.create(household=household, user=user)
    enrollment = begin_enrollment(user)
    confirmed = confirm_enrollment(user, totp_code(enrollment.secret))
    assert confirmed is not None
    assert confirm_recovery_codes_saved(user) is True
    user.refresh_from_db()
    return household, user, enrollment.secret, confirmed.recovery_codes


def _payload(*, email: str, code: str, password: str = NEW_PASSWORD) -> dict[str, str]:
    return {
        "email": email,
        "code": code,
        "new_password1": password,
        "new_password2": password,
    }


def _establish_session(client: Client, user) -> str:  # type: ignore[no-untyped-def]
    client.force_login(user)
    assert client.get(reverse("core:home")).status_code == 200
    session_key = client.session.session_key
    assert session_key is not None
    return session_key


@pytest.mark.django_db
def test_recovery_code_password_reset_revokes_sessions_and_still_requires_mfa(
    recovery_user,
) -> None:  # type: ignore[no-untyped-def]
    household, user, _, codes = recovery_user
    first = Client()
    second = Client()
    first_key = _establish_session(first, user)
    second_key = _establish_session(second, user)
    previous_version = user.session_version

    response = Client().post(
        reverse("identity:password-recovery"),
        _payload(email=user.email.upper(), code=codes[0]),
    )

    assert response.status_code == 200
    assert b"Check by signing in" in response.content
    assert user.email.encode() not in response.content
    user.refresh_from_db()
    assert user.check_password(NEW_PASSWORD)
    assert not user.check_password(CURRENT_PASSWORD)
    assert user.session_version == previous_version + 1
    assert first.get(reverse("core:home")).status_code == 302
    assert second.get(reverse("core:home")).status_code == 302
    assert not Session.objects.filter(session_key__in=(first_key, second_key)).exists()
    event = AuditEvent.objects.get(household=household, action="auth.password_recovered")
    assert event.actor is None
    assert event.before_payload == {"session_version": previous_version}
    assert event.after_payload == {
        "credential_changed": True,
        "factor": "recovery_code",
        "sessions_revoked": True,
        "session_version": previous_version + 1,
    }
    assert NEW_PASSWORD not in str(event.after_payload)
    assert RecoveryCode.objects.get(identifier=codes[0].replace("-", "")[:8]).used_at is not None

    login_client = Client()
    password_response = login_client.post(
        reverse("identity:login"),
        {"username": user.email, "password": NEW_PASSWORD},
    )
    assert password_response.url.startswith(reverse("identity:mfa-verify"))
    mfa_response = login_client.post(reverse("identity:mfa-verify"), {"code": codes[1]})
    assert mfa_response.url == reverse("core:home")


@pytest.mark.django_db
def test_totp_password_recovery_consumes_the_step_before_fresh_login(
    recovery_user,
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # type: ignore[no-untyped-def]
    household, user, secret, codes = recovery_user
    future_time = int(time.time()) + settings.MFA_TOTP_PERIOD_SECONDS
    monkeypatch.setattr("identity.services.mfa.time.time", lambda: future_time)
    code = totp_code(secret, timestamp=future_time)

    response = Client().post(
        reverse("identity:password-recovery"),
        _payload(email=user.email, code=code),
    )

    assert response.status_code == 200
    event = AuditEvent.objects.get(household=household, action="auth.password_recovered")
    assert event.after_payload["factor"] == "totp"
    login_client = Client()
    password_response = login_client.post(
        reverse("identity:login"),
        {"username": user.email, "password": NEW_PASSWORD},
    )
    assert password_response.url.startswith(reverse("identity:mfa-verify"))
    replay = login_client.post(reverse("identity:mfa-verify"), {"code": code})
    assert replay.status_code == 200
    assert b"not accepted" in replay.content
    accepted = login_client.post(reverse("identity:mfa-verify"), {"code": codes[0]})
    assert accepted.url == reverse("core:home")


@pytest.mark.django_db
def test_known_unknown_and_inactive_recovery_responses_do_not_enumerate_accounts(
    recovery_user,
) -> None:  # type: ignore[no-untyped-def]
    household, user, _, _ = recovery_user
    invalid_code = "INVALID-RECOVERY-CODE"
    known = Client().post(
        reverse("identity:password-recovery"),
        _payload(email=user.email, code=invalid_code),
    )
    unknown = Client().post(
        reverse("identity:password-recovery"),
        _payload(email="missing@example.com", code=invalid_code),
    )
    unknown_totp = Client().post(
        reverse("identity:password-recovery"),
        _payload(email="missing@example.com", code="000000"),
    )
    punctuation_only = Client().post(
        reverse("identity:password-recovery"),
        _payload(email=user.email, code="------"),
    )
    LoginThrottle.objects.all().delete()
    user.is_active = False
    user.save(update_fields=("is_active",))
    inactive = Client().post(
        reverse("identity:password-recovery"),
        _payload(email=user.email, code=invalid_code),
    )

    assert (
        known.status_code
        == unknown.status_code
        == unknown_totp.status_code
        == punctuation_only.status_code
        == inactive.status_code
        == 200
    )
    assert known.content == unknown.content == unknown_totp.content == punctuation_only.content
    assert known.content == inactive.content
    assert user.email.encode() not in known.content
    assert b"missing@example.com" not in unknown.content
    assert (
        AuditEvent.objects.filter(
            household=household,
            action="auth.password_recovery_failed",
        ).count()
        == 2
    )
    assert all(user.email not in throttle.key_hash for throttle in LoginThrottle.objects.all())


@pytest.mark.django_db
def test_reused_password_and_invalid_factor_do_not_consume_or_change_credentials(
    recovery_user,
) -> None:  # type: ignore[no-untyped-def]
    household, user, _, codes = recovery_user
    previous_version = user.session_version
    identifier = codes[0].replace("-", "")[:8]

    reused = Client().post(
        reverse("identity:password-recovery"),
        _payload(email=user.email, code=codes[0], password=CURRENT_PASSWORD),
    )
    invalid = Client().post(
        reverse("identity:password-recovery"),
        _payload(email=user.email, code="INVALID-RECOVERY-CODE"),
    )

    assert reused.status_code == invalid.status_code == 200
    assert reused.content == invalid.content
    user.refresh_from_db()
    assert user.check_password(CURRENT_PASSWORD)
    assert user.session_version == previous_version
    assert RecoveryCode.objects.get(identifier=identifier).used_at is None
    assert (
        AuditEvent.objects.filter(
            household=household,
            action="auth.password_recovery_failed",
        ).count()
        == 2
    )


@pytest.mark.django_db
def test_recovery_is_rate_limited_and_never_stores_submitted_values(recovery_user) -> None:  # type: ignore[no-untyped-def]
    _, user, _, _ = recovery_user
    submitted_code = "INVALID-RECOVERY-CODE"
    responses = [
        Client().post(
            reverse("identity:password-recovery"),
            _payload(email=user.email, code=submitted_code),
        )
        for _ in range(settings.LOGIN_RATE_LIMIT_FAILURES)
    ]

    assert all(response.status_code == 200 for response in responses[:-1])
    assert responses[-1].status_code == 429
    assert LoginThrottle.objects.count() == 2
    serialized = " ".join(
        (
            str(tuple(LoginThrottle.objects.values())),
            str(tuple(AuditEvent.objects.values())),
        )
    )
    assert user.email not in serialized
    assert submitted_code not in serialized
    assert NEW_PASSWORD not in serialized


@pytest.mark.django_db
def test_recovery_requires_csrf_valid_passwords_and_an_anonymous_session(
    recovery_user,
) -> None:  # type: ignore[no-untyped-def]
    _, user, _, codes = recovery_user
    anonymous = Client()
    page = anonymous.get(reverse("identity:password-recovery"))
    assert page.status_code == 200
    assert "no-store" in page.headers["Cache-Control"]
    assert b"Recovery never signs you in" in page.content

    invalid_identity = anonymous.post(
        reverse("identity:password-recovery"),
        _payload(email="not-an-email", code=codes[0]),
    )
    assert invalid_identity.status_code == 200
    assert b"valid email address" in invalid_identity.content

    mismatch = anonymous.post(
        reverse("identity:password-recovery"),
        {
            **_payload(email=user.email, code=codes[0], password="password"),
            "new_password2": "different-password",  # pragma: allowlist secret
        },
    )
    assert mismatch.status_code == 200
    assert b"confirmation did not match" in mismatch.content
    assert b"too common" in mismatch.content
    assert not LoginThrottle.objects.exists()

    csrf_client = Client(enforce_csrf_checks=True)
    assert (
        csrf_client.post(
            reverse("identity:password-recovery"),
            _payload(email=user.email, code=codes[0]),
        ).status_code
        == 403
    )

    authenticated = Client()
    authenticated.force_login(user)
    assert authenticated.get(reverse("identity:password-recovery")).status_code == 302


@pytest.mark.django_db
def test_recovery_rolls_back_factor_password_and_sessions_when_audit_append_fails(
    recovery_user,
) -> None:  # type: ignore[no-untyped-def]
    _, user, _, codes = recovery_user
    session_client = Client()
    session_key = _establish_session(session_client, user)
    previous_version = user.session_version
    identifier = codes[0].replace("-", "")[:8]

    with (
        patch("identity.services.recovery.append_event", side_effect=RuntimeError("audit failed")),
        pytest.raises(RuntimeError, match="audit failed"),
    ):
        Client().post(
            reverse("identity:password-recovery"),
            _payload(email=user.email, code=codes[0]),
        )

    user.refresh_from_db()
    assert user.check_password(CURRENT_PASSWORD)
    assert user.session_version == previous_version
    assert RecoveryCode.objects.get(identifier=identifier).used_at is None
    assert Session.objects.filter(session_key=session_key).exists()
    assert not AuditEvent.objects.filter(action="auth.password_recovered").exists()


@pytest.mark.django_db
def test_recovery_audits_every_active_household_membership(recovery_user) -> None:  # type: ignore[no-untyped-def]
    first_household, user, _, codes = recovery_user
    second_household = Household.objects.create(name="Second Recovery Household")
    HouseholdMembership.objects.create(household=second_household, user=user)

    response = Client().post(
        reverse("identity:password-recovery"),
        _payload(email=user.email, code=codes[0]),
    )

    assert response.status_code == 200
    events = AuditEvent.objects.filter(action="auth.password_recovered")
    assert {event.household_id for event in events} == {
        first_household.pk,
        second_household.pk,
    }
