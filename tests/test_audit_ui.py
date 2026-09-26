import time

import pytest
from django.conf import settings
from django.db import connection
from django.test import Client
from django.urls import reverse
from django.utils import timezone

from audit.models import AuditEvent
from audit.services import append_event
from audit.views import event_differences
from households.models import Household, HouseholdMembership
from identity.models import User
from identity.services.mfa import (
    begin_enrollment,
    confirm_enrollment,
    confirm_recovery_codes_saved,
    totp_code,
)
from identity.services.sessions import SESSION_AUTH_VERIFIED_AT

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
    assert b"No edit or delete controls" in response.content
    assert b'method="get"' in response.content
    assert b"Clear audit history" not in response.content


@pytest.mark.django_db
def test_audit_history_pages_enforce_fifty_record_limit(
    client: Client,
    audit_ui_user,
) -> None:  # type: ignore[no-untyped-def]
    household, user = audit_ui_user
    for index in range(50):
        append_event(
            household=household,
            actor=user,
            action="visible.pagination_event",
            entity_type="visible.record",
            entity_id=f"pagination-{index}",
            request_id=f"audit-pagination-{index}",
        )
    client.force_login(user)

    first = client.get(reverse("audit:history"))
    second = client.get(reverse("audit:history"), {"page": "2"})

    assert first.context["page"].paginator.per_page == 50
    assert len(first.context["page"].object_list) == 50
    assert len(second.context["page"].object_list) == 1


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


@pytest.mark.django_db
def test_audit_filters_details_and_detail_access_are_protected(
    client: Client,
    audit_ui_user,
) -> None:  # type: ignore[no-untyped-def]
    household, user = audit_ui_user
    target = append_event(
        household=household,
        actor=user,
        action="budget.item_updated",
        entity_type="budget.item",
        entity_id="budget-item-1",
        request_id="audit-ui-detail-event",
        before={
            "amount": "10.00",
            "settings": {"enabled": False},
            "unchanged": "same",
        },
        after={
            "amount": "25.00",
            "settings": {"enabled": True},
            "unchanged": "same",
            "new_list": ["one", "two"],
        },
        reason="Household correction",
    )
    client.force_login(user)

    filtered = client.get(
        reverse("audit:history"),
        {"action": "budget.item_updated", "q": "budget-item-1"},
    )
    detail = client.get(reverse("audit:detail", args=(target.pk,)))
    hidden = AuditEvent.objects.get(action="hidden.event_created")
    isolated = client.get(reverse("audit:detail", args=(hidden.pk,)))

    assert filtered.status_code == 200
    assert [event.action for event in filtered.context["page"].object_list] == [
        "budget.item_updated"
    ]
    assert detail.status_code == 200
    assert b"Amount" in detail.content
    assert b"10.00" in detail.content
    assert b"25.00" in detail.content
    assert b"Settings" in detail.content
    assert isolated.status_code == 404
    differences = event_differences(target)
    assert {row.field for row in differences} == {"Amount", "New List", "Settings · Enabled"}
    access = AuditEvent.objects.get(action="audit.detail_viewed")
    assert access.entity_id == str(target.pk)
    assert access.after_payload == {"viewed_sequence": target.sequence}


@pytest.mark.django_db
def test_audit_export_requires_recent_auth_is_streamed_safe_scoped_and_audited(
    client: Client,
    audit_ui_user,
) -> None:  # type: ignore[no-untyped-def]
    household, user = audit_ui_user
    append_event(
        household=household,
        actor=user,
        action="visible.formula_event",
        entity_type="visible.record",
        entity_id="formula-record",
        request_id="audit-ui-formula-event",
        reason="=spreadsheet_formula",
        after={"amount": "17.50"},
    )
    client.force_login(user)
    assert client.get(reverse("audit:history")).status_code == 200
    export_url = reverse("audit:export")
    session = client.session
    session[SESSION_AUTH_VERIFIED_AT] = int(time.time()) - settings.RECENT_AUTH_TIMEOUT_SECONDS - 1
    session.save()

    redirect_response = client.get(export_url)
    assert redirect_response.status_code == 302
    assert redirect_response.url.startswith(reverse("identity:reauthenticate"))

    session = client.session
    session[SESSION_AUTH_VERIFIED_AT] = int(time.time())
    session.save()
    response = client.get(export_url)
    content = b"".join(response.streaming_content)  # type: ignore[attr-defined]

    assert response.status_code == 200
    assert response["Content-Type"].startswith("text/csv")
    assert response["Cache-Control"] == "no-store, private"
    assert b"visible.formula_event" in content
    assert b"hidden.event_created" not in content
    assert b"'=spreadsheet_formula" in content
    export_event = AuditEvent.objects.get(action="audit.history_exported")
    assert export_event.actor == user
    assert export_event.after_payload["row_count"] == 2


@pytest.mark.django_db
def test_audit_filter_supports_system_actor_dates_types_and_invalid_ranges(
    client: Client,
    audit_ui_user,
) -> None:  # type: ignore[no-untyped-def]
    household, user = audit_ui_user
    system_event = append_event(
        household=household,
        actor=None,
        action="system.maintenance_checked",
        entity_type="maintenance.check",
        entity_id="maintenance-1",
        request_id="audit-system-filter",
    )
    client.force_login(user)
    local_date = timezone.localdate(system_event.occurred_at).isoformat()

    response = client.get(
        reverse("audit:history"),
        {
            "actor": "system",
            "entity_type": "maintenance.check",
            "date_from": local_date,
            "date_to": local_date,
        },
    )
    invalid = client.get(
        reverse("audit:history"),
        {"date_from": "2026-08-25", "date_to": "2026-08-24"},
    )

    assert [event.pk for event in response.context["page"].object_list] == [system_event.pk]
    assert invalid.context["page"].paginator.count == 0
    assert invalid.context["filter_form"].non_field_errors()


@pytest.mark.django_db
def test_audit_export_fails_closed_on_integrity_failure_and_routes_reject_post(
    client: Client,
    audit_ui_user,
) -> None:  # type: ignore[no-untyped-def]
    household, user = audit_ui_user
    target = AuditEvent.objects.get(household=household)
    table_name = connection.ops.quote_name("audit_auditevent")
    with connection.cursor() as cursor:
        cursor.execute(
            f"UPDATE {table_name} SET reason = %s WHERE id = %s",
            ["tampered", target.pk.hex],
        )
    client.force_login(user)
    session = client.session
    session[SESSION_AUTH_VERIFIED_AT] = int(time.time())
    session.save()

    export_response = client.get(reverse("audit:export"))
    detail_response = client.get(reverse("audit:detail", args=(target.pk,)))

    assert export_response.status_code == 409
    assert detail_response.status_code == 200
    assert b"This access could not be added safely" in detail_response.content
    assert not AuditEvent.objects.filter(action="audit.history_exported").exists()
    assert client.post(reverse("audit:history")).status_code == 405
    assert client.post(reverse("audit:detail", args=(target.pk,))).status_code == 405
    assert client.post(reverse("audit:export")).status_code == 405
