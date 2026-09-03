from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import date, datetime, time
from decimal import Decimal
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.test import Client
from django.urls import reverse
from django.utils import timezone

from audit.models import AuditEvent
from audit.services import append_event
from goals.models import GoalRevision
from goals.services import GoalSpec, create_goal, preview_goal
from households.models import Household, HouseholdMembership
from identity.models import User
from identity.services.mfa import (
    begin_enrollment,
    confirm_enrollment,
    confirm_recovery_codes_saved,
    totp_code,
)
from ledger.models import FinancialAccount, JournalEntry
from ledger.services import create_financial_account
from notifications.models import Notification, NotificationPreference
from notifications.services import (
    dismiss_notification,
    mark_notification_read,
    refresh_household_notifications,
    unread_count,
    update_preferences,
)
from periods.models import PayPeriod
from schedules.models import Occurrence, RecurringSource
from schedules.recurrence import BusinessDayAdjustment, Frequency, RecurrenceRule
from schedules.services import RevisionSpec, create_recurring_source, preview_revision

TEST_PASSWORD = "notifications-test-password"  # pragma: allowlist secret
TEST_TODAY = date(2026, 8, 24)


@dataclass(frozen=True, slots=True)
class NotificationContext:
    household: Household
    user: User
    partner: User
    outsider: User
    period: PayPeriod


@pytest.fixture
def notification_context(db: object) -> NotificationContext:
    household = Household.objects.create(name="Notification Household")
    user = User.objects.create_user(
        email="notify@example.com",
        password=TEST_PASSWORD,
        display_name="Notification User",
    )
    partner = User.objects.create_user(
        email="partner-notify@example.com",
        password=TEST_PASSWORD,
        display_name="Notification Partner",
    )
    outsider = User.objects.create_user(
        email="notification-outsider@example.com",
        password=TEST_PASSWORD,
    )
    HouseholdMembership.objects.create(household=household, user=user)
    HouseholdMembership.objects.create(household=household, user=partner)
    for member in (user, partner):
        enrollment = begin_enrollment(member)
        assert confirm_enrollment(member, totp_code(enrollment.secret)) is not None
        assert confirm_recovery_codes_saved(member) is True
        member.refresh_from_db()
    period = PayPeriod.objects.create(
        household=household,
        start_date=date(2026, 8, 20),
        next_start_date=date(2026, 8, 27),
        status=PayPeriod.Status.OPEN,
        created_by=user,
    )
    return NotificationContext(household, user, partner, outsider, period)


def _aware(value: date = TEST_TODAY) -> datetime:
    return timezone.make_aware(datetime.combine(value, time(hour=12)), ZoneInfo("America/New_York"))


def _occurrence(
    context: NotificationContext,
    *,
    name: str,
    kind: str,
    amount: str,
    expected_date: date,
) -> Occurrence:
    spec = RevisionSpec(
        effective_from=expected_date,
        expected_amount=Decimal(amount),
        rule=RecurrenceRule(frequency=Frequency.ONCE, start_date=expected_date),
        adjustment_policy=BusinessDayAdjustment.NONE,
    )
    preview = preview_revision(spec, preview_from=expected_date)
    source, revision = create_recurring_source(
        household=context.household,
        actor=context.user,
        kind=kind,
        name=name,
        revision_spec=spec,
        expected_preview_fingerprint=preview.fingerprint,
        request_id=f"notify-source-{name.lower().replace(' ', '-')}",
        starts_budget_period=kind == RecurringSource.Kind.INCOME,
    )
    return Occurrence.objects.create(
        source=source,
        source_revision=revision,
        nominal_date=expected_date,
        generated_expected_date=expected_date,
        expected_date=expected_date,
        generated_amount=Decimal(amount),
        planned_amount=Decimal(amount),
        pay_period=context.period,
    )


@pytest.mark.django_db
def test_refresh_generates_due_overdue_missing_income_and_deficit_without_ledger_entries(
    notification_context: NotificationContext,
) -> None:
    _occurrence(
        notification_context,
        name="Power",
        kind=RecurringSource.Kind.FIXED_EXPENSE,
        amount="125.00",
        expected_date=date(2026, 8, 25),
    )
    _occurrence(
        notification_context,
        name="Water",
        kind=RecurringSource.Kind.FIXED_EXPENSE,
        amount="25.00",
        expected_date=date(2026, 8, 21),
    )
    _occurrence(
        notification_context,
        name="Weekly paycheck",
        kind=RecurringSource.Kind.INCOME,
        amount="100.00",
        expected_date=date(2026, 8, 22),
    )

    result = refresh_household_notifications(
        household=notification_context.household,
        now=_aware(),
        today=TEST_TODAY,
    )

    user_kinds = set(
        Notification.objects.filter(recipient=notification_context.user).values_list(
            "kind", flat=True
        )
    )
    assert {
        Notification.Kind.DUE_SOON,
        Notification.Kind.OVERDUE,
        Notification.Kind.MISSING_INCOME,
        Notification.Kind.DEFICIT,
        Notification.Kind.INTEGRITY,
    }.issubset(user_kinds)
    assert result.created >= 10
    assert Notification.objects.filter(recipient=notification_context.partner).exists()
    assert JournalEntry.objects.count() == 0

    second = refresh_household_notifications(
        household=notification_context.household,
        now=_aware(),
        today=TEST_TODAY,
    )
    assert second.created == 0


@pytest.mark.django_db
def test_refresh_resolves_conditions_and_preference_changes_are_audited(
    notification_context: NotificationContext,
) -> None:
    due = _occurrence(
        notification_context,
        name="Internet",
        kind=RecurringSource.Kind.FIXED_EXPENSE,
        amount="75.00",
        expected_date=date(2026, 8, 25),
    )
    refresh_household_notifications(
        household=notification_context.household,
        now=_aware(),
        today=TEST_TODAY,
    )
    assert Notification.objects.filter(
        recipient=notification_context.user,
        kind=Notification.Kind.DUE_SOON,
        resolved_at__isnull=True,
    ).exists()

    values = NotificationPreference.objects.get(
        household=notification_context.household,
        user=notification_context.user,
    ).as_audit_payload()
    values["due_alerts"] = False
    update_preferences(
        household=notification_context.household,
        actor=notification_context.user,
        values=values,
        request_id="notify-preference-update",
    )
    result = refresh_household_notifications(
        household=notification_context.household,
        now=_aware(),
        today=TEST_TODAY,
    )

    assert result.resolved >= 1
    assert (
        Notification.objects.get(
            recipient=notification_context.user,
            kind=Notification.Kind.DUE_SOON,
        ).resolved_at
        is not None
    )
    assert (
        Notification.objects.get(
            recipient=notification_context.partner,
            kind=Notification.Kind.DUE_SOON,
        ).resolved_at
        is None
    )
    assert AuditEvent.objects.filter(action="notification.preferences_updated").exists()
    assert due.status == Occurrence.Status.SCHEDULED

    values["due_alerts"] = True
    update_preferences(
        household=notification_context.household,
        actor=notification_context.user,
        values=values,
        request_id="notify-preference-reenable",
    )
    reopened = refresh_household_notifications(
        household=notification_context.household,
        now=_aware(),
        today=TEST_TODAY,
    )
    assert reopened.reopened >= 1


@pytest.mark.django_db
def test_backup_freshness_and_integrity_failures_create_critical_alerts(
    notification_context: NotificationContext,
    tmp_path: Path,
) -> None:
    marker = tmp_path / ".last-success"
    first = refresh_household_notifications(
        household=notification_context.household,
        now=_aware(),
        today=TEST_TODAY,
        backup_status_path=marker,
    )
    backup = Notification.objects.get(
        recipient=notification_context.user,
        kind=Notification.Kind.BACKUP,
    )
    assert first.created >= 2
    assert backup.severity == Notification.Severity.CRITICAL

    marker.write_text("2026-08-24T12:00:00Z release=test\n", encoding="utf-8")
    timestamp = _aware().timestamp()
    os.utime(marker, (timestamp, timestamp))
    refresh_household_notifications(
        household=notification_context.household,
        now=_aware(),
        today=TEST_TODAY,
        backup_status_path=marker,
    )
    backup.refresh_from_db()
    assert backup.resolved_at is not None

    event = append_event(
        household=notification_context.household,
        actor=notification_context.user,
        action="integrity.test_event",
        entity_type="integrity.test",
        entity_id="integrity-test",
        request_id="notify-integrity-event",
    )
    table_name = connection.ops.quote_name(AuditEvent._meta.db_table)
    with connection.cursor() as cursor:
        cursor.execute(
            f"UPDATE {table_name} SET action = %s WHERE id = %s",
            ["integrity.tampered", event.pk.hex],
        )
    refresh_household_notifications(
        household=notification_context.household,
        now=_aware(),
        today=TEST_TODAY,
    )
    integrity = Notification.objects.filter(
        recipient=notification_context.user,
        kind=Notification.Kind.INTEGRITY,
        severity=Notification.Severity.CRITICAL,
    ).latest("created_at")
    assert "verification failed" in integrity.title.lower()


@pytest.mark.django_db
def test_login_activity_and_goal_milestones_are_deduplicated(
    notification_context: NotificationContext,
) -> None:
    for index in range(3):
        append_event(
            household=notification_context.household,
            actor=None,
            action="auth.login_failed",
            entity_type="identity.user",
            entity_id=notification_context.user.pk,
            request_id=f"notify-login-failed-{index}",
        )
    append_event(
        household=notification_context.household,
        actor=notification_context.user,
        action="auth.login_succeeded",
        entity_type="identity.user",
        entity_id=notification_context.user.pk,
        request_id="notify-login-succeeded",
        after={"authentication_method": "password_totp"},
    )
    checking = create_financial_account(
        household=notification_context.household,
        actor=notification_context.user,
        name="Notify checking",
        account_type=FinancialAccount.AccountType.CHECKING,
        classification=FinancialAccount.Classification.ASSET,
        request_id="notify-checking-account",
    )
    savings = create_financial_account(
        household=notification_context.household,
        actor=notification_context.user,
        name="Notify savings",
        account_type=FinancialAccount.AccountType.SAVINGS,
        classification=FinancialAccount.Classification.ASSET,
        request_id="notify-savings-account",
    )
    spec = GoalSpec(
        effective_from=notification_context.period.start_date,
        name="Notification goal",
        goal_type=GoalRevision.GoalType.SAVINGS,
        target_amount=Decimal("1000.00"),
        target_date=date(2027, 8, 20),
        contribution_per_period=Decimal("0.00"),
        priority=1,
        status=GoalRevision.Status.ACTIVE,
        automatic_excess_allocation=False,
        source_account=checking,
        destination_account=savings,
    )
    preview = preview_goal(
        household=notification_context.household,
        spec=spec,
        opening_amount=Decimal("250.00"),
    )
    goal, _ = create_goal(
        household=notification_context.household,
        actor=notification_context.user,
        spec=spec,
        opening_amount=Decimal("250.00"),
        expected_preview_fingerprint=preview.fingerprint,
        request_id="notify-goal-create",
    )

    refresh_household_notifications(
        household=notification_context.household,
        now=timezone.now(),
        today=TEST_TODAY,
    )

    assert (
        Notification.objects.filter(
            recipient=notification_context.user,
            kind=Notification.Kind.LOGIN_ACTIVITY,
            severity=Notification.Severity.CRITICAL,
        ).count()
        == 1
    )
    assert (
        Notification.objects.filter(
            recipient=notification_context.user,
            kind=Notification.Kind.LOGIN_ACTIVITY,
            title="New authenticated session",
        ).count()
        == 1
    )
    milestone = Notification.objects.get(
        recipient=notification_context.user,
        kind=Notification.Kind.GOAL_MILESTONE,
    )
    assert milestone.source_id == str(goal.pk)
    assert "25%" in milestone.title


@pytest.mark.django_db
def test_password_recovery_alert_is_critical_and_targeted_to_the_account_owner(
    notification_context: NotificationContext,
) -> None:
    event = append_event(
        household=notification_context.household,
        actor=None,
        action="auth.password_recovered",
        entity_type="identity.user",
        entity_id=notification_context.user.pk,
        request_id="notify-password-recovery",
        after={"factor": "recovery_code", "sessions_revoked": True},
    )

    refresh_household_notifications(
        household=notification_context.household,
        now=timezone.now(),
        today=TEST_TODAY,
    )

    alert = Notification.objects.get(
        recipient=notification_context.user,
        title="Password recovery completed",
    )
    assert alert.severity == Notification.Severity.CRITICAL
    assert alert.source_id == str(event.pk)
    assert alert.action_url == reverse("audit:detail", args=(event.pk,))
    assert not Notification.objects.filter(
        recipient=notification_context.partner,
        title="Password recovery completed",
    ).exists()


@pytest.mark.django_db
def test_notification_state_actions_are_recipient_only_idempotent_and_audited(
    notification_context: NotificationContext,
) -> None:
    append_event(
        household=notification_context.household,
        actor=notification_context.user,
        action="notification.seed",
        entity_type="notification.test",
        entity_id="state-actions",
        request_id="notify-state-seed",
    )
    refresh_household_notifications(
        household=notification_context.household,
        now=_aware(),
        today=TEST_TODAY,
    )
    notification = Notification.objects.filter(recipient=notification_context.user).first()
    assert notification is not None

    with pytest.raises(PermissionDenied):
        mark_notification_read(
            notification=notification,
            actor=notification_context.partner,
            request_id="notify-read-partner",
        )
    with pytest.raises(PermissionDenied):
        dismiss_notification(
            notification=notification,
            actor=notification_context.outsider,
            request_id="notify-dismiss-outsider",
        )

    mark_notification_read(
        notification=notification,
        actor=notification_context.user,
        request_id="notify-read-owner",
    )
    mark_notification_read(
        notification=notification,
        actor=notification_context.user,
        request_id="notify-read-owner-again",
    )
    dismiss_notification(
        notification=notification,
        actor=notification_context.user,
        request_id="notify-dismiss-owner",
    )

    notification.refresh_from_db()
    assert notification.read_at is not None
    assert notification.dismissed_at is not None
    assert AuditEvent.objects.filter(action="notification.read").count() == 1
    assert AuditEvent.objects.filter(action="notification.dismissed").count() == 1
    assert (
        unread_count(
            household=notification_context.household,
            user=notification_context.user,
        )
        == 0
    )
    assert (
        unread_count(  # type: ignore[arg-type]
            household=notification_context.household,
            user=AnonymousUser(),
        )
        == 0
    )
    assert (
        unread_count(
            household=notification_context.household,
            user=notification_context.outsider,
        )
        == 0
    )


@pytest.mark.django_db
def test_notification_ui_is_scoped_csrf_protected_and_updates_preferences(
    notification_context: NotificationContext,
) -> None:
    append_event(
        household=notification_context.household,
        actor=notification_context.user,
        action="notification.ui_seed",
        entity_type="notification.test",
        entity_id="ui-actions",
        request_id="notify-ui-seed",
    )
    refresh_household_notifications(
        household=notification_context.household,
        now=_aware(),
        today=TEST_TODAY,
    )
    notification = Notification.objects.filter(recipient=notification_context.user).first()
    partner_notification = Notification.objects.filter(
        recipient=notification_context.partner
    ).first()
    assert notification is not None and partner_notification is not None
    client = Client(enforce_csrf_checks=True)
    client.force_login(notification_context.user)

    listing = client.get(reverse("notifications:list"))
    assert listing.status_code == 200
    assert b"Private in-app alerts" in listing.content
    assert notification.title.encode() in listing.content
    assert partner_notification.pk.hex.encode() not in listing.content
    assert client.post(reverse("notifications:read", args=(notification.pk,))).status_code == 403
    assert client.post(reverse("notifications:refresh")).status_code == 403

    csrf_client = Client()
    csrf_client.force_login(notification_context.user)
    assert csrf_client.get(reverse("notifications:preferences")).status_code == 200
    assert csrf_client.post(reverse("notifications:refresh")).status_code == 302
    assert (
        csrf_client.post(reverse("notifications:read", args=(notification.pk,))).status_code == 302
    )
    notification.refresh_from_db()
    assert notification.read_at is not None
    assert (
        csrf_client.post(reverse("notifications:dismiss", args=(notification.pk,))).status_code
        == 302
    )
    assert csrf_client.get(reverse("notifications:list") + "?status=all").status_code == 200
    assert (
        csrf_client.post(reverse("notifications:read", args=(partner_notification.pk,))).status_code
        == 404
    )
    invalid = csrf_client.post(
        reverse("notifications:preferences"),
        {"upcoming_due_days": "31", "missing_income_grace_days": "31"},
    )
    assert invalid.status_code == 200
    response = csrf_client.post(
        reverse("notifications:preferences"),
        {
            "due_alerts": "on",
            "upcoming_due_days": "5",
            "missing_income_alerts": "on",
            "missing_income_grace_days": "2",
            "deficit_alerts": "on",
            "goal_alerts": "on",
            "backup_alerts": "on",
            "login_alerts": "on",
            "integrity_alerts": "on",
        },
    )
    assert response.status_code == 302
    preference = NotificationPreference.objects.get(
        household=notification_context.household,
        user=notification_context.user,
    )
    assert preference.upcoming_due_days == 5
    assert preference.missing_income_grace_days == 2
    assert AuditEvent.objects.filter(action="notification.preferences_updated").exists()


@pytest.mark.django_db
def test_notification_models_and_refresh_inputs_reject_invalid_state(
    notification_context: NotificationContext,
) -> None:
    now = _aware()
    invalid = Notification(
        household=notification_context.household,
        recipient=notification_context.user,
        kind=Notification.Kind.BACKUP,
        severity=Notification.Severity.WARNING,
        fingerprint="f" * 64,
        title=" ",
        message="Missing title",
        source_type="maintenance.backup",
        source_id="backup",
        occurred_at=now,
        last_evaluated_at=now,
    )
    with pytest.raises(ValidationError, match="title and message"):
        invalid.full_clean()

    invalid.title = "Backup warning"
    invalid.recipient = notification_context.outsider
    with pytest.raises(ValidationError, match="active member"):
        invalid.full_clean()

    invalid.recipient = notification_context.user
    invalid.action_url = "https://example.invalid/phishing"
    with pytest.raises(ValidationError, match="internal application path"):
        invalid.full_clean()

    valid = Notification.objects.create(
        household=notification_context.household,
        recipient=notification_context.user,
        kind=Notification.Kind.BACKUP,
        severity=Notification.Severity.WARNING,
        fingerprint="a" * 64,
        title="Backup warning",
        message="Backup needs attention.",
        source_type="maintenance.backup",
        source_id="backup",
        occurred_at=now,
        last_evaluated_at=now,
    )
    assert "Backup warning" in str(valid)
    assert valid.is_unread is True
    assert valid.internal_action_url == ""
    Notification.objects.filter(pk=valid.pk).update(read_at=now)
    valid.refresh_from_db()
    assert valid.is_unread is False

    invalid_preference = NotificationPreference(
        household=notification_context.household,
        user=notification_context.outsider,
    )
    with pytest.raises(ValidationError, match="active membership"):
        invalid_preference.full_clean()
    preference = NotificationPreference.objects.create(
        household=notification_context.household,
        user=notification_context.user,
    )
    assert "Notification preferences" in str(preference)
    assert preference.as_audit_payload()["upcoming_due_days"] == 3

    for invalid_hours in (0, 721):
        with pytest.raises(ValidationError, match="between 1 and 720"):
            refresh_household_notifications(
                household=notification_context.household,
                backup_max_age_hours=invalid_hours,
            )
    with pytest.raises(ValidationError, match="include a time zone"):
        refresh_household_notifications(
            household=notification_context.household,
            now=datetime(2026, 8, 24, 12),
        )


@pytest.mark.django_db
def test_disabling_alert_families_and_fresh_backup_leave_no_active_conditions(
    notification_context: NotificationContext,
    tmp_path: Path,
) -> None:
    marker = tmp_path / ".last-success"
    marker.write_text("fresh\n", encoding="utf-8")
    timestamp = _aware().timestamp()
    os.utime(marker, (timestamp, timestamp))
    preference = NotificationPreference.objects.create(
        household=notification_context.household,
        user=notification_context.user,
        due_alerts=False,
        missing_income_alerts=False,
        deficit_alerts=False,
        goal_alerts=False,
        backup_alerts=False,
        login_alerts=False,
        integrity_alerts=False,
    )
    NotificationPreference.objects.create(
        household=notification_context.household,
        user=notification_context.partner,
        due_alerts=False,
        missing_income_alerts=False,
        deficit_alerts=False,
        goal_alerts=False,
        backup_alerts=False,
        login_alerts=False,
        integrity_alerts=False,
    )
    result = refresh_household_notifications(
        household=notification_context.household,
        now=_aware(),
        today=TEST_TODAY,
        backup_status_path=marker,
    )
    assert result.active == 0
    assert preference.as_audit_payload()["backup_alerts"] is False


@pytest.mark.django_db
def test_generate_notifications_command_validates_date_and_scopes_household(
    notification_context: NotificationContext,
) -> None:
    call_command(
        "generate_notifications",
        household_id=str(notification_context.household.pk),
        today=TEST_TODAY.isoformat(),
    )
    assert (
        NotificationPreference.objects.filter(household=notification_context.household).count() == 2
    )

    with pytest.raises(CommandError, match="YYYY-MM-DD"):
        call_command("generate_notifications", today="08/24/2026")
