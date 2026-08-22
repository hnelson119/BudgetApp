import time

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.test import Client
from django.urls import reverse

from audit.models import AuditEvent
from households.models import Household, HouseholdMembership
from households.services.access import require_household_membership
from identity.forms import GENERIC_LOGIN_ERROR
from identity.models import LoginThrottle
from identity.services.mfa import (
    begin_enrollment,
    confirm_enrollment,
    confirm_recovery_codes_saved,
    totp_code,
)
from identity.services.sessions import SESSION_LAST_SEEN_AT

TEST_PASSWORD = "correct-horse-battery-test"  # pragma: allowlist secret


@pytest.fixture
def household_user(db):  # type: ignore[no-untyped-def]
    household = Household.objects.create(name="Authentication Household")
    user = get_user_model().objects.create_user(
        email="person@example.com",
        password=TEST_PASSWORD,
        display_name="Person",
    )
    HouseholdMembership.objects.create(household=household, user=user)
    return household, user


@pytest.fixture
def enrolled_household_user(household_user):  # type: ignore[no-untyped-def]
    household, user = household_user
    enrollment = begin_enrollment(user)
    confirmed = confirm_enrollment(user, totp_code(enrollment.secret))
    assert confirmed is not None
    assert confirm_recovery_codes_saved(user) is True
    user.refresh_from_db()
    return household, user, confirmed.recovery_codes, enrollment.secret


def _login(client: Client, *, email: str = "person@example.com", password: str = TEST_PASSWORD):
    return client.post(
        reverse("identity:login"),
        {"username": email, "password": password},
    )


@pytest.mark.django_db
def test_login_page_is_not_cached(client: Client) -> None:
    response = client.get(reverse("identity:login"))

    assert response.status_code == 200
    assert "no-cache" in response.headers["Cache-Control"]
    assert b"Credentials are never shared" in response.content


@pytest.mark.django_db
def test_password_login_establishes_restricted_enrollment_session_and_audit(
    client: Client, household_user
) -> None:  # type: ignore[no-untyped-def]
    household, user = household_user

    response = _login(client)

    assert response.status_code == 302
    assert response.url == reverse("identity:mfa-enroll")
    session = client.session
    assert session["active_household_id"] == str(household.pk)
    assert session["security_user_version"] == user.session_version
    event = AuditEvent.objects.get(action="auth.mfa_enrollment_required")
    assert event.actor == user
    assert event.household == household


@pytest.mark.django_db
def test_login_rejects_external_redirect_target(client: Client, household_user) -> None:  # type: ignore[no-untyped-def]
    response = client.post(
        reverse("identity:login"),
        {
            "username": "person@example.com",
            "password": TEST_PASSWORD,
            "next": "https://attacker.example/steal",
        },
    )

    assert response.status_code == 302
    assert response.url == reverse("identity:mfa-enroll")


@pytest.mark.django_db
def test_unknown_and_inactive_accounts_receive_same_generic_error(
    client: Client, household_user
) -> None:  # type: ignore[no-untyped-def]
    _, user = household_user
    user.is_active = False
    user.save(update_fields=("is_active",))

    inactive_response = _login(client)
    unknown_response = _login(client, email="unknown@example.com")

    expected = GENERIC_LOGIN_ERROR.encode()
    assert inactive_response.status_code == 200
    assert unknown_response.status_code == 200
    assert expected in inactive_response.content
    assert expected in unknown_response.content
    assert b"inactive" not in inactive_response.content.lower()


@pytest.mark.django_db
def test_login_failures_are_rate_limited_without_storing_email(
    client: Client, household_user
) -> None:  # type: ignore[no-untyped-def]
    responses = [
        _login(client, password="incorrect-password")  # pragma: allowlist secret
        for _ in range(settings.LOGIN_RATE_LIMIT_FAILURES)
    ]

    assert all(response.status_code == 200 for response in responses[:-1])
    assert responses[-1].status_code == 429
    assert LoginThrottle.objects.count() == 2
    assert all(
        "person@example.com" not in throttle.key_hash for throttle in LoginThrottle.objects.all()
    )
    assert AuditEvent.objects.filter(action="auth.login_failed").count() == len(responses)


@pytest.mark.django_db
def test_login_requires_csrf(household_user) -> None:  # type: ignore[no-untyped-def]
    client = Client(enforce_csrf_checks=True)

    response = _login(client)

    assert response.status_code == 403
    assert AuditEvent.objects.count() == 0


@pytest.mark.django_db
def test_idle_session_is_terminated(client: Client, household_user) -> None:  # type: ignore[no-untyped-def]
    _login(client)
    session = client.session
    session[SESSION_LAST_SEEN_AT] = int(time.time()) - settings.SESSION_IDLE_TIMEOUT_SECONDS - 1
    session.save()

    response = client.get(reverse("core:home"))

    assert response.status_code == 302
    assert response.url.startswith(reverse("identity:login"))
    assert "_auth_user_id" not in client.session


@pytest.mark.django_db
def test_changed_session_version_revokes_existing_session(client: Client, household_user) -> None:  # type: ignore[no-untyped-def]
    _, user = household_user
    _login(client)
    user.session_version += 1
    user.save(update_fields=("session_version",))

    response = client.get(reverse("core:home"))

    assert response.status_code == 302
    assert "_auth_user_id" not in client.session


@pytest.mark.django_db
def test_logout_is_post_only_and_audited(client: Client, household_user) -> None:  # type: ignore[no-untyped-def]
    _login(client)

    get_response = client.get(reverse("identity:logout"))
    post_response = client.post(reverse("identity:logout"))

    assert get_response.status_code == 405
    assert post_response.status_code == 302
    assert "_auth_user_id" not in client.session
    assert AuditEvent.objects.filter(action="auth.logout").exists()


@pytest.mark.django_db
def test_logout_all_devices_revokes_other_sessions_and_is_audited(
    enrolled_household_user,
) -> None:  # type: ignore[no-untyped-def]
    _, _, codes, _ = enrolled_household_user
    first_client = Client()
    second_client = Client()
    _login(first_client)
    first_client.post(reverse("identity:mfa-verify"), {"code": codes[0]})
    _login(second_client)
    second_client.post(reverse("identity:mfa-verify"), {"code": codes[1]})

    response = first_client.post(reverse("identity:logout-all"))
    second_response = second_client.get(reverse("core:home"))

    assert response.status_code == 302
    assert second_response.status_code == 302
    assert "_auth_user_id" not in first_client.session
    assert "_auth_user_id" not in second_client.session
    assert AuditEvent.objects.filter(action="auth.sessions_revoked").count() == 1


@pytest.mark.django_db
def test_household_authorization_denies_outside_household(household_user) -> None:  # type: ignore[no-untyped-def]
    _, user = household_user
    other_household = Household.objects.create(name="Other Household")

    with pytest.raises(PermissionDenied):
        require_household_membership(user, other_household)
