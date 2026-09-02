import time

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.test import Client
from django.urls import reverse

from audit.models import AuditEvent
from households.models import Household, HouseholdMembership
from identity.services.mfa import (
    begin_enrollment,
    confirm_enrollment,
    confirm_recovery_codes_saved,
    totp_code,
)
from identity.services.sessions import SESSION_AUTH_VERIFIED_AT, active_sessions_for_user

CURRENT_PASSWORD = "account-security-current-passphrase"  # pragma: allowlist secret
NEW_PASSWORD = "account-security-new-passphrase"  # pragma: allowlist secret


@pytest.fixture
def enrolled_user(db):  # type: ignore[no-untyped-def]
    household = Household.objects.create(name="Account Security Household")
    user = get_user_model().objects.create_user(
        email="account-security@example.com",
        password=CURRENT_PASSWORD,
        display_name="Account Owner",
    )
    HouseholdMembership.objects.create(household=household, user=user)
    enrollment = begin_enrollment(user)
    confirmed = confirm_enrollment(user, totp_code(enrollment.secret))
    assert confirmed is not None
    assert confirm_recovery_codes_saved(user) is True
    user.refresh_from_db()
    return household, user, confirmed.recovery_codes


def _login(client: Client, recovery_code: str) -> None:
    password_response = client.post(
        reverse("identity:login"),
        {"username": "account-security@example.com", "password": CURRENT_PASSWORD},
    )
    assert password_response.url.startswith(reverse("identity:mfa-verify"))
    mfa_response = client.post(reverse("identity:mfa-verify"), {"code": recovery_code})
    assert mfa_response.url == reverse("core:home")


def _make_two_sessions(codes: tuple[str, ...]) -> tuple[Client, Client]:
    first = Client()
    second = Client()
    _login(first, codes[0])
    _login(second, codes[1])
    return first, second


@pytest.mark.django_db
def test_account_security_lists_only_active_user_sessions_without_session_keys(
    enrolled_user,
) -> None:  # type: ignore[no-untyped-def]
    _, user, codes = enrolled_user
    first, second = _make_two_sessions(codes)
    other_user = get_user_model().objects.create_user(
        email="other-session@example.com",
        password=CURRENT_PASSWORD,
    )
    other_client = Client()
    other_client.force_login(other_user)

    response = first.get(reverse("identity:account-security"))

    assert response.status_code == 200
    assert "no-store" in response.headers["Cache-Control"]
    rows = response.context["active_sessions"]
    assert len(rows) == 2
    assert rows[0].is_current is True
    assert all(len(row.reference) == 64 for row in rows)
    content = response.content.decode()
    assert first.session.session_key not in content
    assert second.session.session_key not in content
    assert other_client.session.session_key not in content
    assert "detailed device fingerprints" in content
    assert (
        active_sessions_for_user(
            user,
            current_session_key=first.session.session_key,
        )
        == rows
    )


@pytest.mark.django_db
def test_individual_other_session_revocation_is_scoped_and_audited(enrolled_user) -> None:  # type: ignore[no-untyped-def]
    household, user, codes = enrolled_user
    first, second = _make_two_sessions(codes)
    rows = first.get(reverse("identity:account-security")).context["active_sessions"]
    other = next(row for row in rows if not row.is_current)

    response = first.post(
        reverse("identity:session-revoke"),
        {"session_reference": other.reference},
    )

    assert response.status_code == 302
    assert response.url == reverse("identity:account-security")
    assert first.get(reverse("core:home")).status_code == 200
    second_response = second.get(reverse("core:home"))
    assert second_response.status_code == 302
    assert second_response.url.startswith(reverse("identity:login"))
    event = AuditEvent.objects.get(household=household, action="auth.session_revoked")
    assert event.actor == user
    assert event.after_payload == {"scope": "other"}
    assert other.reference not in str(event.after_payload)

    stale_response = first.post(
        reverse("identity:session-revoke"),
        {"session_reference": "0" * 64},
    )
    assert stale_response.status_code == 302
    assert stale_response.url == reverse("identity:account-security")
    assert (
        AuditEvent.objects.filter(household=household, action="auth.session_revoked").count() == 1
    )


@pytest.mark.django_db
def test_current_session_can_be_revoked_without_exposing_its_key(enrolled_user) -> None:  # type: ignore[no-untyped-def]
    household, _, codes = enrolled_user
    client = Client()
    _login(client, codes[0])
    response = client.get(reverse("identity:account-security"))
    current = next(row for row in response.context["active_sessions"] if row.is_current)
    original_key = client.session.session_key

    revoke_response = client.post(
        reverse("identity:session-revoke"),
        {"session_reference": current.reference},
    )

    assert revoke_response.status_code == 302
    assert revoke_response.url == reverse("identity:login")
    assert "_auth_user_id" not in client.session
    assert not Session.objects.filter(session_key=original_key).exists()
    event = AuditEvent.objects.get(household=household, action="auth.session_revoked")
    assert event.after_payload == {"scope": "current"}


@pytest.mark.django_db
def test_session_revocation_requires_recent_authentication_and_rejects_invalid_reference(
    enrolled_user,
) -> None:  # type: ignore[no-untyped-def]
    _, _, codes = enrolled_user
    first, second = _make_two_sessions(codes)
    rows = first.get(reverse("identity:account-security")).context["active_sessions"]
    other = next(row for row in rows if not row.is_current)
    session = first.session
    session[SESSION_AUTH_VERIFIED_AT] = int(time.time()) - settings.RECENT_AUTH_TIMEOUT_SECONDS - 1
    session.save()

    stale_response = first.post(
        reverse("identity:session-revoke"),
        {"session_reference": other.reference},
    )
    invalid_response = first.post(
        reverse("identity:session-revoke"),
        {"session_reference": "invalid"},
    )

    assert stale_response.status_code == 302
    assert stale_response.url.startswith(reverse("identity:reauthenticate"))
    assert invalid_response.status_code == 302
    assert second.get(reverse("core:home")).status_code == 200

    fresh_client = Client()
    _login(fresh_client, codes[2])
    forged_response = fresh_client.post(
        reverse("identity:session-revoke"),
        {"session_reference": "invalid"},
    )
    assert forged_response.status_code == 403


@pytest.mark.django_db
def test_stale_and_malformed_sessions_are_not_presented_as_active(enrolled_user) -> None:  # type: ignore[no-untyped-def]
    _, user, codes = enrolled_user
    client = Client()
    _login(client, codes[0])
    session = client.session
    session["security_started_at"] = 10**100
    session["security_last_seen_at"] = True
    session.save()

    rows = active_sessions_for_user(user, current_session_key=session.session_key)

    assert len(rows) == 1
    assert rows[0].started_at is None
    assert rows[0].last_seen_at is None
    user.session_version += 1
    user.save(update_fields=("session_version",))
    assert active_sessions_for_user(user, current_session_key=session.session_key) == ()


@pytest.mark.django_db
def test_password_change_keeps_current_session_and_revokes_every_other_session(
    enrolled_user,
) -> None:  # type: ignore[no-untyped-def]
    household, user, codes = enrolled_user
    first, second = _make_two_sessions(codes)
    original_session_key = first.session.session_key
    previous_version = user.session_version

    response = first.post(
        reverse("identity:password-change"),
        {
            "old_password": CURRENT_PASSWORD,
            "new_password1": NEW_PASSWORD,
            "new_password2": NEW_PASSWORD,
        },
    )

    assert response.status_code == 302
    assert response.url == reverse("identity:account-security")
    user.refresh_from_db()
    assert user.check_password(NEW_PASSWORD)
    assert not user.check_password(CURRENT_PASSWORD)
    assert user.session_version == previous_version + 1
    assert first.session.session_key != original_session_key
    assert first.get(reverse("core:home")).status_code == 200
    assert second.get(reverse("core:home")).status_code == 302
    assert len(first.get(reverse("identity:account-security")).context["active_sessions"]) == 1
    event = AuditEvent.objects.get(household=household, action="auth.password_changed")
    assert event.before_payload == {"session_version": previous_version}
    assert event.after_payload == {
        "credential_changed": True,
        "other_sessions_revoked": True,
        "session_version": previous_version + 1,
    }
    assert CURRENT_PASSWORD not in str(event.before_payload)
    assert NEW_PASSWORD not in str(event.after_payload)


@pytest.mark.django_db
def test_password_change_requires_recent_auth_and_rejects_wrong_reused_or_weak_passwords(
    enrolled_user,
) -> None:  # type: ignore[no-untyped-def]
    _, user, codes = enrolled_user
    client = Client()
    _login(client, codes[0])
    session = client.session
    session[SESSION_AUTH_VERIFIED_AT] = int(time.time()) - settings.RECENT_AUTH_TIMEOUT_SECONDS - 1
    session.save()

    stale_response = client.get(reverse("identity:password-change"))
    assert stale_response.status_code == 302
    assert stale_response.url.startswith(reverse("identity:reauthenticate"))

    session = client.session
    session[SESSION_AUTH_VERIFIED_AT] = int(time.time())
    session.save()
    for old_password, new_password, expected in (
        ("wrong-current", NEW_PASSWORD, "old password was entered incorrectly"),
        (CURRENT_PASSWORD, CURRENT_PASSWORD, "must be different"),
        (CURRENT_PASSWORD, "password", "too common"),
    ):
        response = client.post(
            reverse("identity:password-change"),
            {
                "old_password": old_password,
                "new_password1": new_password,
                "new_password2": new_password,
            },
        )
        assert response.status_code == 200
        assert expected in str(response.context["form"].errors).lower()

    user.refresh_from_db()
    assert user.check_password(CURRENT_PASSWORD)
    assert not AuditEvent.objects.filter(action="auth.password_changed").exists()


@pytest.mark.django_db
def test_logout_all_devices_requires_recent_authentication(enrolled_user) -> None:  # type: ignore[no-untyped-def]
    _, _, codes = enrolled_user
    first, second = _make_two_sessions(codes)
    session = first.session
    session[SESSION_AUTH_VERIFIED_AT] = int(time.time()) - settings.RECENT_AUTH_TIMEOUT_SECONDS - 1
    session.save()

    response = first.post(reverse("identity:logout-all"))

    assert response.status_code == 302
    assert response.url.startswith(reverse("identity:reauthenticate"))
    assert first.get(reverse("core:home")).status_code == 200
    assert second.get(reverse("core:home")).status_code == 200


@pytest.mark.django_db
def test_account_security_mutations_require_login_csrf_and_supported_methods(
    enrolled_user,
) -> None:  # type: ignore[no-untyped-def]
    _, user, _ = enrolled_user
    anonymous = Client()
    assert anonymous.get(reverse("identity:account-security")).status_code == 302
    assert anonymous.post(reverse("identity:session-revoke")).status_code == 302

    csrf_client = Client(enforce_csrf_checks=True)
    csrf_client.force_login(user)
    assert csrf_client.get(reverse("identity:account-security")).status_code == 200
    page = csrf_client.get(reverse("identity:account-security"))
    assert page.status_code == 200
    current = next(row for row in page.context["active_sessions"] if row.is_current)

    assert csrf_client.get(reverse("identity:session-revoke")).status_code == 405
    assert csrf_client.get(reverse("identity:logout-all")).status_code == 405
    assert (
        csrf_client.post(
            reverse("identity:session-revoke"),
            {"session_reference": current.reference},
        ).status_code
        == 403
    )
    assert (
        csrf_client.post(
            reverse("identity:password-change"),
            {
                "old_password": CURRENT_PASSWORD,
                "new_password1": NEW_PASSWORD,
                "new_password2": NEW_PASSWORD,
            },
        ).status_code
        == 403
    )
    assert csrf_client.post(reverse("identity:logout-all")).status_code == 403


@pytest.mark.django_db
def test_account_security_events_are_protected_for_every_active_household(
    enrolled_user,
) -> None:  # type: ignore[no-untyped-def]
    first_household, user, codes = enrolled_user
    second_household = Household.objects.create(name="Second Active Household")
    HouseholdMembership.objects.create(household=second_household, user=user)
    first, second = _make_two_sessions(codes)
    for client in (first, second):
        session = client.session
        session["active_household_id"] = str(first_household.pk)
        session.save()
    other = next(
        row
        for row in first.get(reverse("identity:account-security")).context["active_sessions"]
        if not row.is_current
    )

    response = first.post(
        reverse("identity:session-revoke"),
        {"session_reference": other.reference},
    )

    assert response.status_code == 302
    events = AuditEvent.objects.filter(action="auth.session_revoked").order_by("household_id")
    assert {event.household_id for event in events} == {
        first_household.pk,
        second_household.pk,
    }
    assert all(event.after_payload == {"scope": "other"} for event in events)
    assert second.get(reverse("core:home")).status_code == 302


@pytest.mark.django_db
def test_session_revocation_rolls_back_without_an_active_audit_boundary(enrolled_user) -> None:  # type: ignore[no-untyped-def]
    household, user, codes = enrolled_user
    first, second = _make_two_sessions(codes)
    other = next(
        row
        for row in first.get(reverse("identity:account-security")).context["active_sessions"]
        if not row.is_current
    )
    other_session_key = second.session.session_key
    HouseholdMembership.objects.filter(household=household, user=user).update(is_active=False)

    response = first.post(
        reverse("identity:session-revoke"),
        {"session_reference": other.reference},
    )

    assert response.status_code == 403
    assert Session.objects.filter(session_key=other_session_key).exists()
    assert not AuditEvent.objects.filter(action="auth.session_revoked").exists()
