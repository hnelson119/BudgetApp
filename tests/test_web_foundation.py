from datetime import date, time

import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.urls import reverse

from core.forms import html_date_input, html_time_input
from households.models import Household, HouseholdMembership

TEST_PASSWORD = "safe-test-pass"  # pragma: allowlist secret


def test_html_date_and_time_widgets_render_portable_values() -> None:
    date_widget = html_date_input()
    time_widget = html_time_input()

    assert date_widget.input_type == "date"
    assert date_widget.format_value(date(2026, 8, 24)) == "2026-08-24"
    assert time_widget.input_type == "time"
    assert time_widget.format_value(time(19, 5, 48)) == "19:05"


@pytest.mark.django_db
def test_email_is_normalized_and_case_insensitively_unique() -> None:
    user_model = get_user_model()
    user = user_model.objects.create_user(email="  PERSON@Example.COM ", password=TEST_PASSWORD)

    assert user.email == "person@example.com"

    with pytest.raises(IntegrityError):
        user_model.objects.create_user(email="Person@example.com", password=TEST_PASSWORD)


@pytest.mark.django_db
def test_home_page_requires_authentication(client) -> None:  # type: ignore[no-untyped-def]
    response = client.get(reverse("core:home"))

    assert response.status_code == 302
    assert response.url.startswith(reverse("identity:login"))


@pytest.mark.django_db
def test_home_page_loads_for_household_member(client) -> None:  # type: ignore[no-untyped-def]
    user = get_user_model().objects.create_user(email="member@example.com", password=TEST_PASSWORD)
    household = Household.objects.create(name="Test Household")
    HouseholdMembership.objects.create(user=user, household=household)
    client.force_login(user)

    response = client.get(reverse("core:home"))

    assert response.status_code == 302
    assert response.url == reverse("identity:mfa-enroll")


def test_liveness_endpoint(client) -> None:  # type: ignore[no-untyped-def]
    response = client.get(reverse("core:health-live"))

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.django_db
def test_readiness_endpoint_checks_database(client) -> None:  # type: ignore[no-untyped-def]
    response = client.get(reverse("core:health-ready"))

    assert response.status_code == 200
    assert response.json() == {"status": "ready", "database": "ok"}
