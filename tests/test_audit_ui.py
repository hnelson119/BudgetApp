import pytest
from django.db import connection
from django.urls import reverse

from audit.services import append_event
from households.models import Household, HouseholdMembership
from identity.models import User
from identity.services.mfa import (
    begin_enrollment,
    confirm_enrollment,
    confirm_recovery_codes_saved,
    totp_code,
)

TEST_PASSWORD = "audit-ui-test-password"  # pragma: allowlist secret


@pytest.fixture
def audit_ui_user(db):  # type: ignore[no-untyped-def]
    household = Household.objects.create(name="Visible Household")
    user = User.objects.create_user(
        email="audit-ui@example.com",
        password=TEST_PASSWORD,
        display_name="Visible Person",
    )
    HouseholdMembership.objects.create(household=household, user=user)
    enrollment = begin_enrollment(user)
    confirmed = confirm_enrollment(user, totp_code(enrollment.secret))
    assert confirmed is not None
    assert confirm_recovery_codes_saved(user) is True
    user.refresh_from_db()
    append_event(
        household=household,
        actor=user,
        action="visible.event_created",
        entity_type="visible.record",
        entity_id="visible-1",
        request_id="audit-ui-request-1234",
    )

    other_household = Household.objects.create(name="Hidden Household")
    other_user = User.objects.create_user(email="hidden@example.com", password=TEST_PASSWORD)
    HouseholdMembership.objects.create(household=other_household, user=other_user)
    append_event(
        household=other_household,
        actor=other_user,
        action="hidden.event_created",
        entity_type="hidden.record",
        entity_id="hidden-1",
        request_id="audit-ui-request-5678",
    )
    return household, user


@pytest.mark.django_db
def test_audit_history_is_household_scoped_read_only_and_not_cached(
    client,
    audit_ui_user,
) -> None:  # type: ignore[no-untyped-def]
    _, user = audit_ui_user
    client.force_login(user)

    response = client.get(reverse("audit:history"))

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store, private"
    assert b"Chain verified" in response.content
    assert b"visible.event_created" in response.content
    assert b"Visible Person" in response.content
    assert b"hidden.event_created" not in response.content
    assert b"Audit records cannot be edited or deleted" in response.content
    assert b"<form" not in response.content


@pytest.mark.django_db
def test_audit_history_prominently_warns_when_chain_verification_fails(
    client,
    audit_ui_user,
) -> None:  # type: ignore[no-untyped-def]
    household, user = audit_ui_user
    table_name = connection.ops.quote_name("audit_auditevent")
    with connection.cursor() as cursor:
        cursor.execute(
            f"UPDATE {table_name} SET action = %s WHERE household_id = %s",
            ["tampered.event", household.pk.hex],
        )
    client.force_login(user)

    response = client.get(reverse("audit:history"))

    assert response.status_code == 200
    assert b"Audit integrity check failed" in response.content
    assert b"Stop financial changes" in response.content
