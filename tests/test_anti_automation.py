from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import timedelta

import pytest
from django.test import Client, override_settings
from django.urls import reverse
from django.utils import timezone

from audit.models import AuditEvent
from households.models import Household, HouseholdMembership
from identity.models import ApplicationThrottle, User
from identity.services.application_throttling import consume_application_budget
from identity.services.mfa import (
    begin_enrollment,
    confirm_enrollment,
    confirm_recovery_codes_saved,
    totp_code,
)
from identity.services.sessions import SESSION_AUTH_VERIFIED_AT
from imports.models import ImportBatch

TEST_PASSWORD = "anti-automation-test-password"  # pragma: allowlist secret


@dataclass(frozen=True, slots=True)
class AntiAutomationContext:
    household: Household
    user: User


@pytest.fixture
def anti_automation_context(db: object) -> AntiAutomationContext:
    household = Household.objects.create(name="Anti-automation Household")
    user = User.objects.create_user(
        email="anti-automation@example.com",
        password=TEST_PASSWORD,
    )
    HouseholdMembership.objects.create(household=household, user=user)
    enrollment = begin_enrollment(user)
    assert confirm_enrollment(user, totp_code(enrollment.secret)) is not None
    assert confirm_recovery_codes_saved(user) is True
    user.refresh_from_db()
    return AntiAutomationContext(household=household, user=user)


def _authenticate(client: Client, context: AntiAutomationContext) -> None:
    client.force_login(context.user)
    session = client.session
    session[SESSION_AUTH_VERIFIED_AT] = int(time.time())
    session.save()
    assert client.get(reverse("core:home")).status_code == 200


@pytest.mark.django_db
def test_application_budget_is_atomic_bounded_and_resets_after_its_window(
    anti_automation_context: AntiAutomationContext,
) -> None:
    decisions = [
        consume_application_budget(
            user=anti_automation_context.user,
            scope="test-scope",
            maximum=2,
            window_seconds=60,
        )
        for _ in range(3)
    ]

    assert [decision.allowed for decision in decisions] == [True, True, False]
    assert 1 <= decisions[-1].retry_after_seconds <= 60
    throttle = ApplicationThrottle.objects.get(
        user=anti_automation_context.user,
        scope="test-scope",
    )
    assert throttle.request_count == 2

    ApplicationThrottle.objects.filter(pk=throttle.pk).update(
        window_started_at=timezone.now() - timedelta(seconds=61)
    )
    reset = consume_application_budget(
        user=anti_automation_context.user,
        scope="test-scope",
        maximum=2,
        window_seconds=60,
    )

    assert reset.allowed is True
    throttle.refresh_from_db()
    assert throttle.request_count == 1


@pytest.mark.django_db
@override_settings(
    APPLICATION_MUTATION_RATE_LIMIT=1,
    APPLICATION_MUTATION_RATE_WINDOW_SECONDS=300,
)
def test_all_authenticated_mutations_share_a_fail_closed_budget(
    client: Client,
    anti_automation_context: AntiAutomationContext,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _authenticate(client, anti_automation_context)

    first = client.post(reverse("notifications:refresh"))
    with caplog.at_level("WARNING", logger="security"):
        blocked = client.post(reverse("notifications:refresh"))
    logout = client.post(reverse("identity:logout"))

    assert first.status_code == 302
    assert blocked.status_code == 429
    assert blocked.headers["Retry-After"] == "300"
    assert blocked.headers["Cache-Control"] == "no-store, private"
    assert blocked.headers["Pragma"] == "no-cache"
    assert blocked.headers["X-Error-Reference"]
    assert logout.status_code == 302
    assert logout.headers["Location"] == reverse("identity:login")
    assert (
        ApplicationThrottle.objects.get(
            user=anti_automation_context.user,
            scope="authenticated-mutation",
        ).request_count
        == 1
    )
    assert any(
        record.getMessage() == "Authenticated mutation rate limited."
        and record.event == "anti_automation.rate_limited"
        and record.scope == "mutation"
        for record in caplog.records
    )


@pytest.mark.django_db
@override_settings(DATA_EXPORT_RATE_LIMIT=1, DATA_EXPORT_RATE_WINDOW_SECONDS=900)
def test_transaction_and_audit_exports_share_a_tighter_data_budget(
    client: Client,
    anti_automation_context: AntiAutomationContext,
) -> None:
    _authenticate(client, anti_automation_context)

    transaction_export = client.get(reverse("spending:transaction-export"), {"scope": "all"})
    blocked_audit_export = client.get(reverse("audit:export"))

    assert transaction_export.status_code == 200
    assert transaction_export.streaming is True
    assert blocked_audit_export.status_code == 429
    assert blocked_audit_export.headers["Retry-After"] == "900"
    assert (
        ApplicationThrottle.objects.get(
            user=anti_automation_context.user,
            scope="data-export",
        ).request_count
        == 1
    )
    assert AuditEvent.objects.filter(action="spending.transactions_exported").count() == 1
    assert not AuditEvent.objects.filter(action="audit.history_exported").exists()


@pytest.mark.django_db
@override_settings(
    APPLICATION_MUTATION_RATE_LIMIT=100,
    CSV_IMPORT_RATE_LIMIT=1,
    CSV_IMPORT_RATE_WINDOW_SECONDS=900,
)
def test_rejected_csv_uploads_consume_the_import_budget_before_parsing(
    client: Client,
    anti_automation_context: AntiAutomationContext,
) -> None:
    _authenticate(client, anti_automation_context)

    rejected = client.post(reverse("imports:upload"), {})
    blocked = client.post(reverse("imports:upload"), {})

    assert rejected.status_code == 200
    assert blocked.status_code == 429
    assert blocked.headers["Retry-After"] == "900"
    assert not ImportBatch.objects.exists()
    assert (
        ApplicationThrottle.objects.get(
            user=anti_automation_context.user,
            scope="csv-import",
        ).request_count
        == 1
    )


@pytest.mark.django_db
@override_settings(
    APPLICATION_MUTATION_RATE_LIMIT=100,
    EXPENSIVE_CALCULATION_RATE_LIMIT=1,
    EXPENSIVE_CALCULATION_RATE_WINDOW_SECONDS=900,
)
def test_get_projection_and_post_refresh_share_the_expensive_calculation_budget(
    client: Client,
    anti_automation_context: AntiAutomationContext,
) -> None:
    _authenticate(client, anti_automation_context)

    comparison = client.get(
        reverse("debts:payoff-comparison"),
        {"monthly_extra": "0.00", "start_date": "2026-09-26", "maximum_years": "40"},
    )
    blocked_refresh = client.post(reverse("notifications:refresh"))

    assert comparison.status_code == 200
    assert blocked_refresh.status_code == 429
    assert blocked_refresh.headers["Retry-After"] == "900"
    assert (
        ApplicationThrottle.objects.get(
            user=anti_automation_context.user,
            scope="expensive-calculation",
        ).request_count
        == 1
    )
