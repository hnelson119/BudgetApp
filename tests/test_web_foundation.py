import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.urls import reverse

TEST_PASSWORD = "safe-test-pass"  # pragma: allowlist secret


@pytest.mark.django_db
def test_email_is_normalized_and_case_insensitively_unique() -> None:
    user_model = get_user_model()
    user = user_model.objects.create_user(email="  PERSON@Example.COM ", password=TEST_PASSWORD)

    assert user.email == "person@example.com"

    with pytest.raises(IntegrityError):
        user_model.objects.create_user(email="Person@example.com", password=TEST_PASSWORD)


def test_home_page_loads(client) -> None:  # type: ignore[no-untyped-def]
    response = client.get(reverse("core:home"))

    assert response.status_code == 200
    assert b"paycheck-to-paycheck" in response.content


def test_liveness_endpoint(client) -> None:  # type: ignore[no-untyped-def]
    response = client.get(reverse("core:health-live"))

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.django_db
def test_readiness_endpoint_checks_database(client) -> None:  # type: ignore[no-untyped-def]
    response = client.get(reverse("core:health-ready"))

    assert response.status_code == 200
    assert response.json() == {"status": "ready", "database": "ok"}
