from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Case, IntegerField, QuerySet, When
from django.urls import reverse
from django.utils import timezone

from audit.models import AuditCheckpoint, AuditEvent, AuditHead
from audit.services import append_event, verify_household_chain
from budgets.services.summary import build_period_summary
from goals.models import GoalRevision
from goals.services import goal_progress_rows
from households.models import Household, HouseholdMembership
from households.services.access import require_household_membership
from identity.models import User
from notifications.models import Notification, NotificationPreference
from periods.models import PayPeriod
from schedules.models import Occurrence, RecurringSource

_ACTIVE_OCCURRENCE_STATUSES = (
    Occurrence.Status.SCHEDULED,
    Occurrence.Status.MOVED,
    Occurrence.Status.OVERRIDDEN,
)
_CONDITIONAL_KINDS = (
    Notification.Kind.DUE_SOON,
    Notification.Kind.OVERDUE,
    Notification.Kind.MISSING_INCOME,
    Notification.Kind.DEFICIT,
    Notification.Kind.BACKUP,
    Notification.Kind.INTEGRITY,
)


@dataclass(frozen=True, slots=True)
class NotificationRefreshResult:
    created: int
    reopened: int
    resolved: int
    active: int


@dataclass(frozen=True, slots=True)
class NotificationSpec:
    kind: str
    severity: str
    identity: str
    title: str
    message: str
    action_url: str
    source_type: str
    source_id: str
    occurred_at: datetime


def _fingerprint(spec: NotificationSpec) -> str:
    return hashlib.sha256(f"{spec.kind}:{spec.identity}".encode()).hexdigest()


def _local_midday(value: date, household: Household) -> datetime:
    return timezone.make_aware(
        datetime.combine(value, datetime.min.time()).replace(hour=12),
        ZoneInfo(household.time_zone),
    )


def _preference(household: Household, user: User) -> NotificationPreference:
    preference, _ = NotificationPreference.objects.get_or_create(
        household=household,
        user=user,
    )
    return preference


def _upsert(
    *,
    household: Household,
    recipient: User,
    spec: NotificationSpec,
    evaluated_at: datetime,
) -> tuple[Notification, bool, bool]:
    fingerprint = _fingerprint(spec)
    notification, created = Notification.objects.get_or_create(
        household=household,
        recipient=recipient,
        fingerprint=fingerprint,
        defaults={
            "kind": spec.kind,
            "severity": spec.severity,
            "title": spec.title,
            "message": spec.message,
            "action_url": spec.action_url,
            "source_type": spec.source_type,
            "source_id": spec.source_id,
            "occurred_at": spec.occurred_at,
            "last_evaluated_at": evaluated_at,
        },
    )
    reopened = False
    if not created:
        reopened = notification.resolved_at is not None
        Notification.objects.filter(pk=notification.pk).update(
            severity=spec.severity,
            title=spec.title,
            message=spec.message,
            action_url=spec.action_url,
            last_evaluated_at=evaluated_at,
            resolved_at=None,
        )
        notification.refresh_from_db()
    return notification, created, reopened


def _occurrence_specs(
    *,
    household: Household,
    preference: NotificationPreference,
    today: date,
) -> list[NotificationSpec]:
    specs: list[NotificationSpec] = []
    oldest = today - timedelta(days=90)
    latest = today + timedelta(days=preference.upcoming_due_days)
    occurrences = (
        Occurrence.objects.filter(
            source__household=household,
            expected_date__gte=oldest,
            expected_date__lte=latest,
            status__in=_ACTIVE_OCCURRENCE_STATUSES,
        )
        .select_related("source", "pay_period")
        .order_by("expected_date", "source__name")
    )
    for occurrence in occurrences:
        action_url = (
            reverse("budgets:detail", args=(occurrence.pay_period_id,))
            if occurrence.pay_period_id
            else reverse("core:home")
        )
        amount = f"${occurrence.planned_amount:,.2f}"
        if occurrence.source.kind in (
            RecurringSource.Kind.FIXED_EXPENSE,
            RecurringSource.Kind.DEBT_PAYMENT,
        ):
            if not preference.due_alerts:
                continue
            if occurrence.expected_date < today:
                specs.append(
                    NotificationSpec(
                        kind=Notification.Kind.OVERDUE,
                        severity=Notification.Severity.WARNING,
                        identity=f"occurrence:{occurrence.pk}:overdue",
                        title=f"{occurrence.source.name} is overdue",
                        message=(
                            f"{amount} was due {occurrence.expected_date:%b %d, %Y} "
                            "and has not been marked paid."
                        ),
                        action_url=action_url,
                        source_type="schedule.occurrence",
                        source_id=str(occurrence.pk),
                        occurred_at=_local_midday(occurrence.expected_date, household),
                    )
                )
            elif occurrence.expected_date <= latest:
                specs.append(
                    NotificationSpec(
                        kind=Notification.Kind.DUE_SOON,
                        severity=Notification.Severity.INFO,
                        identity=f"occurrence:{occurrence.pk}:due-soon",
                        title=f"{occurrence.source.name} is due soon",
                        message=f"{amount} is due {occurrence.expected_date:%b %d, %Y}.",
                        action_url=action_url,
                        source_type="schedule.occurrence",
                        source_id=str(occurrence.pk),
                        occurred_at=_local_midday(today, household),
                    )
                )
        elif (
            occurrence.source.kind == RecurringSource.Kind.INCOME
            and preference.missing_income_alerts
            and occurrence.expected_date + timedelta(days=preference.missing_income_grace_days)
            <= today
        ):
            specs.append(
                NotificationSpec(
                    kind=Notification.Kind.MISSING_INCOME,
                    severity=Notification.Severity.WARNING,
                    identity=f"occurrence:{occurrence.pk}:missing-income",
                    title=f"Expected paycheck from {occurrence.source.name}",
                    message=(
                        f"{amount} was expected {occurrence.expected_date:%b %d, %Y} "
                        "and has not been marked received."
                    ),
                    action_url=action_url,
                    source_type="schedule.occurrence",
                    source_id=str(occurrence.pk),
                    occurred_at=_local_midday(occurrence.expected_date, household),
                )
            )
    return specs


def _deficit_specs(
    *,
    household: Household,
    preference: NotificationPreference,
    today: date,
) -> list[NotificationSpec]:
    if not preference.deficit_alerts:
        return []
    specs: list[NotificationSpec] = []
    periods = PayPeriod.objects.filter(
        household=household,
        next_start_date__gt=today,
        start_date__lte=today + timedelta(days=31),
    ).order_by("start_date")[:3]
    for period in periods:
        summary = build_period_summary(household=household, period=period, today=today)
        if summary.unallocated_excess >= 0:
            continue
        specs.append(
            NotificationSpec(
                kind=Notification.Kind.DEFICIT,
                severity=Notification.Severity.CRITICAL,
                identity=f"period:{period.pk}:deficit",
                title="Paycheck period has a projected deficit",
                message=(
                    f"The {period.start_date:%b %d}-{period.display_end_date:%b %d} plan "
                    f"is short by ${abs(summary.unallocated_excess):,.2f}."
                ),
                action_url=reverse("budgets:detail", args=(period.pk,)),
                source_type="periods.pay_period",
                source_id=str(period.pk),
                occurred_at=_local_midday(today, household),
            )
        )
    return specs


def _goal_specs(
    *,
    household: Household,
    preference: NotificationPreference,
    today: date,
) -> list[NotificationSpec]:
    if not preference.goal_alerts:
        return []
    specs: list[NotificationSpec] = []
    for row in goal_progress_rows(household=household, on_date=today):
        reached = max(
            (value for value in (25, 50, 75, 100) if row.progress_percent >= value),
            default=0,
        )
        if reached == 0:
            continue
        completed = reached == 100 or row.revision.status == GoalRevision.Status.COMPLETED
        specs.append(
            NotificationSpec(
                kind=Notification.Kind.GOAL_MILESTONE,
                severity=(
                    Notification.Severity.INFO if not completed else Notification.Severity.WARNING
                ),
                identity=f"goal:{row.goal.pk}:milestone:{reached}",
                title=f"{row.revision.name} reached {reached}%",
                message=(
                    f"Current progress is ${row.current_amount:,.2f} of "
                    f"${row.revision.target_amount:,.2f}."
                ),
                action_url=reverse("goals:detail", args=(row.goal.pk,)),
                source_type="goals.goal",
                source_id=str(row.goal.pk),
                occurred_at=_local_midday(today, household),
            )
        )
    return specs


def _login_specs(
    *,
    household: Household,
    preference: NotificationPreference,
    evaluated_at: datetime,
) -> list[NotificationSpec]:
    if not preference.login_alerts:
        return []
    since = evaluated_at - timedelta(hours=24)
    events = list(
        AuditEvent.objects.filter(
            household=household,
            occurred_at__gte=since,
            action__in=(
                "auth.login_succeeded",
                "auth.login_failed",
                "auth.mfa_failed",
                "auth.password_recovered",
                "auth.password_recovery_failed",
            ),
        ).order_by("sequence")
    )
    specs: list[NotificationSpec] = []
    for event in events:
        if event.action == "auth.login_succeeded" and event.actor_id == preference.user_id:
            specs.append(
                NotificationSpec(
                    kind=Notification.Kind.LOGIN_ACTIVITY,
                    severity=Notification.Severity.INFO,
                    identity=f"audit:{event.pk}:login-succeeded",
                    title="New authenticated session",
                    message="Your account completed password and authenticator verification.",
                    action_url=reverse("audit:detail", args=(event.pk,)),
                    source_type="audit.event",
                    source_id=str(event.pk),
                    occurred_at=event.occurred_at,
                )
            )
        if event.action == "auth.password_recovered" and event.entity_id == str(preference.user_id):
            specs.append(
                NotificationSpec(
                    kind=Notification.Kind.LOGIN_ACTIVITY,
                    severity=Notification.Severity.CRITICAL,
                    identity=f"audit:{event.pk}:password-recovered",
                    title="Password recovery completed",
                    message=(
                        "Your password was reset with an MFA recovery factor and all prior "
                        "sessions were ended."
                    ),
                    action_url=reverse("audit:detail", args=(event.pk,)),
                    source_type="audit.event",
                    source_id=str(event.pk),
                    occurred_at=event.occurred_at,
                )
            )
    failures: dict[str, list[AuditEvent]] = {}
    for event in events:
        if event.action in (
            "auth.login_failed",
            "auth.mfa_failed",
            "auth.password_recovery_failed",
        ):
            failures.setdefault(event.entity_id, []).append(event)
    for entity_id, failed_events in failures.items():
        if len(failed_events) < 3:
            continue
        latest = failed_events[-1]
        specs.append(
            NotificationSpec(
                kind=Notification.Kind.LOGIN_ACTIVITY,
                severity=Notification.Severity.CRITICAL,
                identity=f"login-failures:{entity_id}:{latest.occurred_at.date().isoformat()}",
                title="Repeated sign-in failures detected",
                message=(
                    f"{len(failed_events)} failed password, authenticator, or recovery attempts "
                    "were "
                    "recorded in the last 24 hours."
                ),
                action_url=reverse("audit:history") + f"?action={latest.action}",
                source_type="identity.user",
                source_id=entity_id,
                occurred_at=latest.occurred_at,
            )
        )
    return specs


def _integrity_specs(
    *,
    household: Household,
    preference: NotificationPreference,
    evaluated_at: datetime,
) -> list[NotificationSpec]:
    if not preference.integrity_alerts:
        return []
    integrity = verify_household_chain(household)
    if not integrity.valid:
        return [
            NotificationSpec(
                kind=Notification.Kind.INTEGRITY,
                severity=Notification.Severity.CRITICAL,
                identity=f"integrity-failure:{integrity.failure_sequence}",
                title="Protected audit verification failed",
                message=(
                    "Stop financial changes and follow the trusted integrity and recovery "
                    "procedure."
                ),
                action_url=reverse("audit:history"),
                source_type="audit.chain",
                source_id=str(household.pk),
                occurred_at=evaluated_at,
            )
        ]
    head = AuditHead.objects.filter(household=household).first()
    latest_checkpoint = AuditCheckpoint.objects.filter(household=household).first()
    if head is not None and (
        latest_checkpoint is None
        or latest_checkpoint.external_copied_at < evaluated_at - timedelta(hours=36)
    ):
        return [
            NotificationSpec(
                kind=Notification.Kind.INTEGRITY,
                severity=Notification.Severity.WARNING,
                identity="integrity-checkpoint-overdue",
                title="External audit checkpoint is overdue",
                message="The protected audit chain needs a fresh signed external checkpoint.",
                action_url=reverse("audit:history"),
                source_type="audit.checkpoint",
                source_id=str(household.pk),
                occurred_at=evaluated_at,
            )
        ]
    return []


def _backup_specs(
    *,
    household: Household,
    preference: NotificationPreference,
    evaluated_at: datetime,
    backup_status_path: Path | None,
    backup_max_age_hours: int,
) -> list[NotificationSpec] | None:
    if backup_status_path is None:
        return None
    if not preference.backup_alerts:
        return []
    stale = True
    try:
        resolved = backup_status_path.resolve(strict=True)
        if resolved.is_file() and resolved.stat().st_size <= 1024:
            modified = datetime.fromtimestamp(
                resolved.stat().st_mtime,
                tz=timezone.get_current_timezone(),
            )
            stale = modified < evaluated_at - timedelta(hours=backup_max_age_hours)
    except OSError:
        stale = True
    if not stale:
        return []
    return [
        NotificationSpec(
            kind=Notification.Kind.BACKUP,
            severity=Notification.Severity.CRITICAL,
            identity="backup-overdue",
            title="Verified backup is overdue",
            message=(
                f"No successful encrypted backup marker has been recorded in the last "
                f"{backup_max_age_hours} hours."
            ),
            action_url=reverse("audit:history"),
            source_type="maintenance.backup",
            source_id=str(household.pk),
            occurred_at=evaluated_at,
        )
    ]


@transaction.atomic
def refresh_household_notifications(
    *,
    household: Household,
    now: datetime | None = None,
    today: date | None = None,
    backup_status_path: Path | None = None,
    backup_max_age_hours: int = 36,
) -> NotificationRefreshResult:
    if backup_max_age_hours < 1 or backup_max_age_hours > 24 * 30:
        raise ValidationError("Backup alert age must be between 1 and 720 hours.")
    evaluated_at = now or timezone.now()
    if timezone.is_naive(evaluated_at):
        raise ValidationError("Notification evaluation time must include a time zone.")
    local_today = today or timezone.localdate(
        evaluated_at,
        timezone=ZoneInfo(household.time_zone),
    )
    active_members = list(
        HouseholdMembership.objects.filter(household=household, is_active=True)
        .select_related("user")
        .order_by("joined_at")
    )
    created_count = 0
    reopened_count = 0
    active_count = 0
    active_conditional: dict[object, set[str]] = {}
    evaluated_kinds: dict[object, set[str]] = {}
    for membership in active_members:
        preference = _preference(household, membership.user)
        specs = [
            *_occurrence_specs(household=household, preference=preference, today=local_today),
            *_deficit_specs(household=household, preference=preference, today=local_today),
            *_goal_specs(household=household, preference=preference, today=local_today),
            *_login_specs(
                household=household,
                preference=preference,
                evaluated_at=evaluated_at,
            ),
            *_integrity_specs(
                household=household,
                preference=preference,
                evaluated_at=evaluated_at,
            ),
        ]
        evaluated: set[str] = {
            Notification.Kind.DUE_SOON.value,
            Notification.Kind.OVERDUE.value,
            Notification.Kind.MISSING_INCOME.value,
            Notification.Kind.DEFICIT.value,
            Notification.Kind.INTEGRITY.value,
        }
        backup_specs = _backup_specs(
            household=household,
            preference=preference,
            evaluated_at=evaluated_at,
            backup_status_path=backup_status_path,
            backup_max_age_hours=backup_max_age_hours,
        )
        if backup_specs is not None:
            specs.extend(backup_specs)
            evaluated.add(Notification.Kind.BACKUP)
        evaluated_kinds[membership.user_id] = evaluated
        active_conditional[membership.user_id] = set()
        for spec in specs:
            notification, created, reopened = _upsert(
                household=household,
                recipient=membership.user,
                spec=spec,
                evaluated_at=evaluated_at,
            )
            created_count += int(created)
            reopened_count += int(reopened)
            active_count += 1
            if spec.kind in _CONDITIONAL_KINDS:
                active_conditional[membership.user_id].add(notification.fingerprint)

    resolved_count = 0
    for membership in active_members:
        query = Notification.objects.filter(
            household=household,
            recipient=membership.user,
            kind__in=evaluated_kinds[membership.user_id],
            resolved_at__isnull=True,
        )
        active_fingerprints = active_conditional[membership.user_id]
        if active_fingerprints:
            query = query.exclude(fingerprint__in=active_fingerprints)
        resolved_count += query.update(resolved_at=evaluated_at, last_evaluated_at=evaluated_at)
    return NotificationRefreshResult(
        created=created_count,
        reopened=reopened_count,
        resolved=resolved_count,
        active=active_count,
    )


def notifications_for_user(
    *,
    household: Household,
    user: User,
    include_history: bool = False,
) -> QuerySet[Notification]:
    require_household_membership(user, household)
    notifications = Notification.objects.filter(household=household, recipient=user)
    if not include_history:
        notifications = notifications.filter(dismissed_at__isnull=True, resolved_at__isnull=True)
    severity_rank = Case(
        When(severity=Notification.Severity.CRITICAL, then=3),
        When(severity=Notification.Severity.WARNING, then=2),
        default=1,
        output_field=IntegerField(),
    )
    return notifications.alias(severity_rank=severity_rank).order_by(
        "read_at",
        "-severity_rank",
        "-occurred_at",
    )


def unread_count(*, household: Household, user: User) -> int:
    if not user.is_authenticated:
        return 0
    if not HouseholdMembership.objects.filter(
        household=household,
        user=user,
        is_active=True,
    ).exists():
        return 0
    return Notification.objects.filter(
        household=household,
        recipient=user,
        read_at__isnull=True,
        dismissed_at__isnull=True,
        resolved_at__isnull=True,
    ).count()


@transaction.atomic
def mark_notification_read(
    *,
    notification: Notification,
    actor: User,
    request_id: str,
) -> Notification:
    require_household_membership(actor, notification.household)
    if notification.recipient_id != actor.pk:
        raise PermissionDenied
    locked = Notification.objects.select_for_update().get(pk=notification.pk)
    if locked.read_at is None:
        read_at = timezone.now()
        Notification.objects.filter(pk=locked.pk).update(read_at=read_at)
        append_event(
            household=locked.household,
            actor=actor,
            action="notification.read",
            entity_type="notification",
            entity_id=locked.pk,
            request_id=request_id,
            after={"kind": locked.kind},
        )
        locked.read_at = read_at
    return locked


@transaction.atomic
def dismiss_notification(
    *,
    notification: Notification,
    actor: User,
    request_id: str,
) -> Notification:
    require_household_membership(actor, notification.household)
    if notification.recipient_id != actor.pk:
        raise PermissionDenied
    locked = Notification.objects.select_for_update().get(pk=notification.pk)
    if locked.dismissed_at is None:
        dismissed_at = timezone.now()
        Notification.objects.filter(pk=locked.pk).update(
            read_at=locked.read_at or dismissed_at,
            dismissed_at=dismissed_at,
        )
        append_event(
            household=locked.household,
            actor=actor,
            action="notification.dismissed",
            entity_type="notification",
            entity_id=locked.pk,
            request_id=request_id,
            after={"kind": locked.kind},
        )
        locked.read_at = locked.read_at or dismissed_at
        locked.dismissed_at = dismissed_at
    return locked


@transaction.atomic
def update_preferences(
    *,
    household: Household,
    actor: User,
    values: dict[str, object],
    request_id: str,
) -> NotificationPreference:
    require_household_membership(actor, household)
    preference = _preference(household, actor)
    before = preference.as_audit_payload()
    editable = tuple(before)
    for name in editable:
        if name not in values:
            raise ValidationError(f"Missing notification preference {name}.")
        setattr(preference, name, values[name])
    preference.full_clean()
    preference.save(update_fields=(*editable, "updated_at"))
    after = preference.as_audit_payload()
    if before != after:
        append_event(
            household=household,
            actor=actor,
            action="notification.preferences_updated",
            entity_type="notification.preference",
            entity_id=preference.pk,
            request_id=request_id,
            before=before,
            after=after,
        )
    return preference
