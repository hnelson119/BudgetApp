import time

import pytest
from django.conf import settings
from django.contrib import admin
from django.test import Client
from django.urls import reverse

from households.models import Household, HouseholdMembership
from identity.models import User
from identity.services.mfa import (
    begin_enrollment,
    confirm_enrollment,
    confirm_recovery_codes_saved,
    totp_code,
)
from identity.services.sessions import SESSION_AUTH_VERIFIED_AT, SESSION_MFA_VERIFIED

PASSWORD = "administration-regression-passphrase"  # pragma: allowlist secret
REPLACEMENT_PASSWORD = "replacement-admin-passphrase"  # pragma: allowlist secret
pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def admin_urls(settings):  # type: ignore[no-untyped-def]
    settings.ROOT_URLCONF = "config.urls"


@pytest.fixture
def administrator() -> tuple[User, tuple[str, ...]]:
    user = User.objects.create_superuser(email="administrator@example.com", password=PASSWORD)
    household = Household.objects.create(name="Admin Test Household")
    HouseholdMembership.objects.create(household=household, user=user)
    enrollment = begin_enrollment(user)
    confirmed = confirm_enrollment(user, totp_code(enrollment.secret))
    assert confirmed is not None
    assert confirm_recovery_codes_saved(user)
    user.refresh_from_db()
    return user, confirmed.recovery_codes


def _login(client: Client, user: User, code: str) -> None:
    response = client.post(
        reverse("identity:login"), {"username": user.email, "password": PASSWORD}
    )
    assert response.status_code == 302
    assert response.url.startswith(reverse("identity:mfa-verify"))
    assert "_auth_user_id" not in client.session
    assert SESSION_MFA_VERIFIED not in client.session
    response = client.post(reverse("identity:mfa-verify"), {"code": code})
    assert response.status_code == 302
    assert client.session[SESSION_MFA_VERIFIED] is True


@pytest.mark.parametrize("method", ("get", "post"))
def test_admin_login_never_authenticates_a_password_only_session(
    administrator: tuple[User, tuple[str, ...]], method: str
) -> None:
    user, _ = administrator
    client = Client()
    response = getattr(client, method)(
        reverse("admin:login"),
        {"username": user.email, "password": PASSWORD, "next": "https://attacker.example/"},
    )

    assert response.status_code == 302
    assert response.url == reverse("identity:login") + "?next=/admin/"
    assert "no-cache" in response.headers["Cache-Control"]
    assert "_auth_user_id" not in client.session
    assert SESSION_MFA_VERIFIED not in client.session


def test_admin_requires_completed_application_mfa(
    administrator: tuple[User, tuple[str, ...]],
) -> None:
    user, codes = administrator
    client = Client()
    client.post(reverse("identity:login"), {"username": user.email, "password": PASSWORD})
    response = client.get(reverse("admin:index"))
    assert response.status_code == 302
    assert response.url.startswith(reverse("admin:login"))

    client.post(reverse("identity:mfa-verify"), {"code": codes[0]})
    response = client.get(reverse("admin:index"))
    assert response.status_code == 200
    assert "no-store" in response.headers["Cache-Control"]


def test_legacy_password_only_session_cannot_gain_admin_access_from_enrollment_state(
    administrator: tuple[User, tuple[str, ...]],
) -> None:
    user, codes = administrator
    client = Client()
    client.force_login(user)

    response = client.get(reverse("admin:index"), follow=True)
    assert response.status_code == 200
    assert response.request["PATH_INFO"] == reverse("identity:reauthenticate")
    assert SESSION_MFA_VERIFIED not in client.session

    old_key = client.session.session_key
    response = client.post(
        reverse("identity:reauthenticate") + "?next=/admin/",
        {"password": PASSWORD, "code": codes[0]},
    )
    assert response.status_code == 302
    assert response.url == "/admin/"
    assert client.session.session_key != old_key
    assert client.session[SESSION_MFA_VERIFIED] is True
    assert client.get(reverse("admin:index")).status_code == 200


@pytest.mark.parametrize("wrong_factor", ("password", "code"))
def test_failed_reauthentication_cannot_grant_admin_proof(
    administrator: tuple[User, tuple[str, ...]], wrong_factor: str
) -> None:
    user, codes = administrator
    client = Client()
    client.force_login(user)
    credentials = {"password": PASSWORD, "code": codes[0]}
    credentials[wrong_factor] = "invalid-factor"

    response = client.post(reverse("identity:reauthenticate"), credentials)
    assert response.status_code == 200
    assert SESSION_MFA_VERIFIED not in client.session
    assert client.get(reverse("admin:index")).status_code == 302


def test_stale_admin_session_cannot_change_a_password(
    administrator: tuple[User, tuple[str, ...]],
) -> None:
    user, codes = administrator
    client = Client()
    _login(client, user, codes[0])
    session = client.session
    session[SESSION_AUTH_VERIFIED_AT] = int(time.time()) - settings.RECENT_AUTH_TIMEOUT_SECONDS
    session.save()
    previous_hash = user.password

    response = client.post(
        reverse("admin:auth_user_password_change", args=(user.pk,)),
        {"password1": REPLACEMENT_PASSWORD, "password2": REPLACEMENT_PASSWORD},
    )
    assert response.status_code == 302
    assert response.url.startswith(reverse("admin:login"))
    user.refresh_from_db()
    assert user.password == previous_hash
    redirected = client.get(response.url, follow=True)
    assert redirected.request["PATH_INFO"] == reverse("identity:reauthenticate")


def test_non_staff_member_cannot_enter_or_loop_through_admin_login(
    administrator: tuple[User, tuple[str, ...]],
) -> None:
    user, codes = administrator
    user.is_staff = False
    user.save(update_fields=("is_staff",))
    client = Client()
    _login(client, user, codes[0])

    response = client.get(reverse("admin:index"), follow=True)
    assert response.status_code == 403
    assert len(response.redirect_chain) == 1


def test_admin_user_editor_cannot_write_internal_authentication_state(
    administrator: tuple[User, tuple[str, ...]],
) -> None:
    user, codes = administrator
    client = Client()
    _login(client, user, codes[0])

    response = client.get(reverse("admin:identity_user_change", args=(user.pk,)))
    assert response.status_code == 200
    fields = response.context["adminform"].form.fields
    protected = {
        "session_version",
        "mfa_enrolled_at",
        "last_authenticated_at",
        "last_login",
        "date_joined",
    }
    assert protected.isdisjoint(fields)
    assert protected <= set(admin.site.get_model_admin(User).readonly_fields)


def test_admin_retains_csrf_protection(administrator: tuple[User, tuple[str, ...]]) -> None:
    user, codes = administrator
    client = Client()
    _login(client, user, codes[0])
    csrf_client = Client(enforce_csrf_checks=True)
    csrf_client.cookies[settings.SESSION_COOKIE_NAME] = client.cookies[settings.SESSION_COOKIE_NAME]

    response = csrf_client.post(reverse("admin:logout"))
    assert response.status_code == 403
    assert csrf_client.get(reverse("admin:index")).status_code == 200
