from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from unittest.mock import patch

import pytest
from django.core.exceptions import ValidationError
from django.test import Client
from django.urls import reverse

from audit.models import AuditEvent
from core.logging import RedactingJsonFormatter
from goals.models import Goal, GoalContribution, GoalRevision
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
from periods.models import PayPeriod
from periods.services import close_period
from reserves.services import reserve_balance

TEST_PASSWORD = "goal-ui-test-password"  # pragma: allowlist secret


@dataclass(frozen=True, slots=True)
class GoalUiContext:
    household: Household
    user: User
    outsider: User
    periods: tuple[PayPeriod, ...]
    checking: FinancialAccount
    savings: FinancialAccount


def _mfa_ready(user: User) -> None:
    enrollment = begin_enrollment(user)
    assert confirm_enrollment(user, totp_code(enrollment.secret)) is not None
    assert confirm_recovery_codes_saved(user) is True
    user.refresh_from_db()


@pytest.fixture
def goal_ui_context(db: object, monkeypatch: pytest.MonkeyPatch) -> GoalUiContext:
    monkeypatch.setattr("goals.views._today", lambda _: date(2026, 8, 22))
    monkeypatch.setattr("core.views.timezone.localdate", lambda **_: date(2026, 8, 22))
    household = Household.objects.create(name="Goal UI Household")
    user = User.objects.create_user(email="goal-ui@example.com", password=TEST_PASSWORD)
    outsider = User.objects.create_user(
        email="goal-ui-outsider@example.com",
        password=TEST_PASSWORD,
    )
    HouseholdMembership.objects.create(household=household, user=user)
    periods = tuple(
        PayPeriod.objects.create(
            household=household,
            start_date=start,
            next_start_date=end,
            status=PayPeriod.Status.OPEN,
            created_by=user,
        )
        for start, end in (
            (date(2026, 8, 20), date(2026, 8, 27)),
            (date(2026, 8, 27), date(2026, 9, 3)),
            (date(2026, 9, 3), date(2026, 9, 10)),
        )
    )
    checking = create_financial_account(
        household=household,
        actor=user,
        name="Household checking",
        account_type=FinancialAccount.AccountType.CHECKING,
        classification=FinancialAccount.Classification.ASSET,
        request_id="goal-ui-checking",
    )
    savings = create_financial_account(
        household=household,
        actor=user,
        name="Emergency savings",
        account_type=FinancialAccount.AccountType.SAVINGS,
        classification=FinancialAccount.Classification.ASSET,
        request_id="goal-ui-savings",
    )
    return GoalUiContext(household, user, outsider, periods, checking, savings)


def _payload(context: GoalUiContext) -> dict[str, str]:
    return {
        "effective_from": "2026-08-20",
        "name": "Emergency Fund",
        "goal_type": GoalRevision.GoalType.SAVINGS,
        "opening_amount": "200.00",
        "target_amount": "2000.00",
        "target_date": "2027-08-20",
        "contribution_per_period": "100.00",
        "priority": "1",
        "status": GoalRevision.Status.ACTIVE,
        "source_account": str(context.checking.pk),
        "destination_account": str(context.savings.pk),
        "linked_debt": "",
        "notes": "Three months of essentials",
    }


def _service_goal(
    context: GoalUiContext,
    *,
    effective_from: date,
    name: str = "Emergency Fund",
    target: str = "2000.00",
    priority: int = 1,
    automatic: bool = False,
) -> Goal:
    spec = GoalSpec(
        effective_from=effective_from,
        name=name,
        goal_type=GoalRevision.GoalType.SAVINGS,
        target_amount=Decimal(target),
        target_date=date(2027, 8, 20),
        contribution_per_period=Decimal("0.00"),
        priority=priority,
        status=GoalRevision.Status.ACTIVE,
        automatic_excess_allocation=automatic,
        source_account=context.checking,
        destination_account=context.savings,
    )
    preview = preview_goal(
        household=context.household,
        spec=spec,
        opening_amount=Decimal("0.00"),
    )
    goal, _ = create_goal(
        household=context.household,
        actor=context.user,
        spec=spec,
        opening_amount=Decimal("0.00"),
        expected_preview_fingerprint=preview.fingerprint,
        request_id=f"goal-ui-create-{name.lower().replace(' ', '-')}",
    )
    return goal


@pytest.mark.django_db
def test_goal_pages_require_login_csrf_and_supported_methods(
    goal_ui_context: GoalUiContext,
) -> None:
    anonymous = Client()
    for url in (reverse("goals:list"), reverse("goals:create")):
        response = anonymous.get(url)
        assert response.status_code == 302
        assert response.headers["Location"].startswith(reverse("identity:login"))

    _mfa_ready(goal_ui_context.user)
    csrf_client = Client(enforce_csrf_checks=True)
    csrf_client.force_login(goal_ui_context.user)
    assert csrf_client.post(reverse("goals:create"), _payload(goal_ui_context)).status_code == 403

    method_client = Client()
    method_client.force_login(goal_ui_context.user)
    assert method_client.put(reverse("goals:create"), data={}).status_code == 405
    assert method_client.post(reverse("goals:list"), data={}).status_code == 405


@pytest.mark.django_db
def test_goal_preview_confirm_dashboard_budget_and_scheduled_actual_flow(
    client: Client,
    goal_ui_context: GoalUiContext,
) -> None:
    _mfa_ready(goal_ui_context.user)
    client.force_login(goal_ui_context.user)
    payload = _payload(goal_ui_context)
    payload["action"] = "preview"
    preview_response = client.post(reverse("goals:create"), payload)
    assert preview_response.status_code == 200
    assert b"Next paycheck periods" in preview_response.content
    preview = preview_response.context["preview"]
    assert preview.next_period_starts[:2] == (date(2026, 8, 20), date(2026, 8, 27))

    payload.update(
        {
            "action": "confirm",
            "preview_fingerprint": preview.fingerprint,
        }
    )
    created = client.post(reverse("goals:create"), payload)
    assert created.status_code == 302
    goal = Goal.objects.get()
    occurrence = goal.funding_plan.source.occurrences.order_by("nominal_date").first()
    assert occurrence is not None

    list_response = client.get(reverse("goals:list"))
    assert list_response.status_code == 200
    assert b"Emergency Fund" in list_response.content
    assert b'class="mobile-nav"' in list_response.content
    assert b"Automatic excess allocation stays off" not in list_response.content
    assert list_response.headers["Cache-Control"] == "no-store, private"

    dashboard = client.get(reverse("core:home"))
    assert dashboard.status_code == 200
    assert b"Protected actual progress" in dashboard.content
    assert b"Emergency Fund" in dashboard.content

    budget = client.get(reverse("budgets:detail", args=(goal_ui_context.periods[0].pk,)))
    assert budget.status_code == 200
    assert b"Record contribution" in budget.content

    actual = client.post(
        reverse("goals:occurrence-contribute", args=(goal.pk, occurrence.pk)),
        {
            "submission_token": "77777777-7777-4777-8777-777777777777",
            "pay_period": str(goal_ui_context.periods[0].pk),
            "amount": "100.00",
            "effective_date": "2026-08-20",
            "reason": "Weekly funding",
        },
    )
    assert actual.status_code == 302
    contribution = GoalContribution.objects.get()
    assert contribution.occurrence_id == occurrence.pk
    assert contribution.journal_entry.entry_type == JournalEntry.EntryType.GOAL_CONTRIBUTION
    occurrence.refresh_from_db()
    assert occurrence.status == occurrence.Status.COMPLETED


@pytest.mark.django_db
def test_goal_reserve_ui_previews_and_records_non_income_allocation(
    client: Client,
    goal_ui_context: GoalUiContext,
) -> None:
    first, posting = goal_ui_context.periods[:2]
    close_period(
        pay_period=first,
        actor=goal_ui_context.user,
        closing_surplus=Decimal("929.90"),
        request_id="goal-ui-close-reserve",
    )
    goal = _service_goal(goal_ui_context, effective_from=posting.start_date)
    _mfa_ready(goal_ui_context.user)
    client.force_login(goal_ui_context.user)
    url = reverse("goals:reserve-allocate", args=(goal.pk, posting.pk))
    preview_response = client.post(
        url,
        {"amount": "300.00", "reason": "Emergency cushion", "action": "preview"},
    )
    assert preview_response.status_code == 200
    assert b"$929.90" in preview_response.content
    assert b"$629.90" in preview_response.content
    preview = preview_response.context["preview"]

    confirmed = client.post(
        url,
        {
            "amount": "300.00",
            "reason": "Emergency cushion",
            "action": "confirm",
            "preview_fingerprint": preview.fingerprint,
        },
    )
    assert confirmed.status_code == 302
    assert reserve_balance(goal_ui_context.household) == Decimal("629.90")
    assert GoalContribution.objects.get().reserve_entry_id is not None
    assert not JournalEntry.objects.filter(entry_type=JournalEntry.EntryType.INCOME).exists()
    assert not JournalEntry.objects.filter(category__isnull=False).exists()


@pytest.mark.django_db
def test_goal_detail_and_forms_are_scoped_to_active_household(
    client: Client,
    goal_ui_context: GoalUiContext,
) -> None:
    hidden_household = Household.objects.create(name="Hidden Household")
    HouseholdMembership.objects.create(
        household=hidden_household,
        user=goal_ui_context.outsider,
    )
    hidden_period = PayPeriod.objects.create(
        household=hidden_household,
        start_date=date(2026, 8, 20),
        next_start_date=date(2026, 8, 27),
        status=PayPeriod.Status.OPEN,
        created_by=goal_ui_context.outsider,
    )
    hidden_source = create_financial_account(
        household=hidden_household,
        actor=goal_ui_context.outsider,
        name="Hidden checking",
        account_type=FinancialAccount.AccountType.CHECKING,
        classification=FinancialAccount.Classification.ASSET,
        request_id="goal-ui-hidden-source",
    )
    hidden_destination = create_financial_account(
        household=hidden_household,
        actor=goal_ui_context.outsider,
        name="Hidden savings",
        account_type=FinancialAccount.AccountType.SAVINGS,
        classification=FinancialAccount.Classification.ASSET,
        request_id="goal-ui-hidden-destination",
    )
    spec = GoalSpec(
        effective_from=hidden_period.start_date,
        name="Hidden goal",
        goal_type=GoalRevision.GoalType.SAVINGS,
        target_amount=Decimal("1000.00"),
        target_date=None,
        contribution_per_period=Decimal("0.00"),
        priority=1,
        status=GoalRevision.Status.ACTIVE,
        automatic_excess_allocation=False,
        source_account=hidden_source,
        destination_account=hidden_destination,
    )
    preview = preview_goal(
        household=hidden_household,
        spec=spec,
        opening_amount=Decimal("0.00"),
    )
    hidden_goal, _ = create_goal(
        household=hidden_household,
        actor=goal_ui_context.outsider,
        spec=spec,
        opening_amount=Decimal("0.00"),
        expected_preview_fingerprint=preview.fingerprint,
        request_id="goal-ui-hidden-create",
    )
    _mfa_ready(goal_ui_context.user)
    client.force_login(goal_ui_context.user)

    assert client.get(reverse("goals:detail", args=(hidden_goal.pk,))).status_code == 404
    create_page = client.get(reverse("goals:create"))
    assert create_page.status_code == 200
    assert b"Hidden checking" not in create_page.content
    assert b"Hidden goal" not in client.get(reverse("goals:list")).content


@pytest.mark.django_db
def test_manual_goal_contribution_rejects_a_retried_submission_token(
    client: Client,
    goal_ui_context: GoalUiContext,
    caplog: pytest.LogCaptureFixture,
) -> None:
    goal = _service_goal(goal_ui_context, effective_from=date(2026, 8, 20))
    _mfa_ready(goal_ui_context.user)
    client.force_login(goal_ui_context.user)
    url = reverse("goals:contribute", args=(goal.pk,))
    payload = {
        "submission_token": "99999999-9999-4999-8999-999999999999",
        "pay_period": str(goal_ui_context.periods[0].pk),
        "amount": "75.00",
        "effective_date": "2026-08-23",
        "reason": "Manual transfer retry",
    }

    accepted = client.post(url, payload)
    with caplog.at_level(logging.WARNING, logger="security"):
        retried = client.post(
            url,
            payload,
            headers={"X-Request-ID": "goal-contribution-replay"},
        )

    assert accepted.status_code == 302
    assert retried.status_code == 200
    assert b"idempotency key has already been used" in retried.content
    assert GoalContribution.objects.count() == 1
    assert (
        JournalEntry.objects.filter(entry_type=JournalEntry.EntryType.GOAL_CONTRIBUTION).count()
        == 1
    )
    assert AuditEvent.objects.filter(action="goal.contribution_recorded").count() == 1
    rejected = [
        record
        for record in caplog.records
        if getattr(record, "event", None) == "goal.contribution_rejected"
    ]
    assert len(rejected) == 1
    assert rejected[0].error_reference == "goal-contribution-replay"  # type: ignore[attr-defined]


@pytest.mark.django_db
def test_invalid_goal_forms_emit_minimized_security_events(
    client: Client,
    goal_ui_context: GoalUiContext,
    caplog: pytest.LogCaptureFixture,
) -> None:
    goal = _service_goal(goal_ui_context, effective_from=date(2026, 8, 20))
    _mfa_ready(goal_ui_context.user)
    client.force_login(goal_ui_context.user)
    canary = "PRIVATE_GOAL_REJECTION_CANARY"
    requests = (
        (reverse("goals:create"), {"name": canary, "reason": canary}, "goal-reject-create"),
        (
            reverse("goals:revise", args=(goal.pk,)),
            {"name": canary, "reason": canary},
            "goal-reject-revision",
        ),
        (
            reverse("goals:status", args=(goal.pk, GoalRevision.Status.PAUSED)),
            {"name": canary, "reason": canary},
            "goal-reject-status",
        ),
        (
            reverse("goals:contribute", args=(goal.pk,)),
            {"name": canary, "reason": canary},
            "goal-reject-contribution",
        ),
        (
            reverse(
                "goals:reserve-allocate",
                args=(goal.pk, goal_ui_context.periods[0].pk),
            ),
            {"name": canary, "reason": canary},
            "goal-reject-reserve",
        ),
        (
            reverse("goals:priority-allocate", args=(goal_ui_context.periods[0].pk,)),
            {"amount": "invalid", "reason": canary},
            "goal-reject-priority",
        ),
    )

    with caplog.at_level(logging.WARNING, logger="security"):
        responses = [
            client.post(
                url,
                data,
                headers={"X-Request-ID": request_id},
            )
            for url, data, request_id in requests
        ]

    assert [response.status_code for response in responses] == [200] * 6
    expected_events = [
        "goal.create_rejected",
        "goal.revision_rejected",
        "goal.status_rejected",
        "goal.contribution_rejected",
        "goal.reserve_allocation_rejected",
        "goal.priority_allocation_rejected",
    ]
    records = [
        record for record in caplog.records if getattr(record, "event", None) in expected_events
    ]
    assert [record.event for record in records] == expected_events  # type: ignore[attr-defined]
    assert [record.error_reference for record in records] == [  # type: ignore[attr-defined]
        request_id for _url, _data, request_id in requests
    ]
    assert all(record.levelno == logging.WARNING for record in records)
    payloads = [json.loads(RedactingJsonFormatter().format(record)) for record in records]
    assert all(canary not in json.dumps(payload) for payload in payloads)
    assert all(
        not {
            "amount",
            "name",
            "notes",
            "reason",
            "goal_id",
            "period_id",
            "status",
        }.intersection(payload)
        for payload in payloads
    )


@pytest.mark.django_db
def test_service_level_goal_rejections_emit_minimized_security_events(
    client: Client,
    goal_ui_context: GoalUiContext,
    caplog: pytest.LogCaptureFixture,
) -> None:
    goal = _service_goal(goal_ui_context, effective_from=date(2026, 8, 20))
    _mfa_ready(goal_ui_context.user)
    client.force_login(goal_ui_context.user)
    canary = "PRIVATE_GOAL_SERVICE_REJECTION_CANARY"
    create_payload = _payload(goal_ui_context)
    create_payload["action"] = "preview"
    workflows = (
        (
            "goals.views.preview_goal",
            reverse("goals:create"),
            create_payload,
            "goal.create_rejected",
            "goal-service-create",
        ),
        (
            "goals.views.preview_goal",
            reverse("goals:revise", args=(goal.pk,)),
            {
                "effective_from": "2026-08-23",
                "name": "Synthetic revision",
                "goal_type": GoalRevision.GoalType.SAVINGS,
                "target_amount": "2500.00",
                "target_date": "2027-08-20",
                "contribution_per_period": "125.00",
                "priority": "2",
                "status": GoalRevision.Status.ACTIVE,
                "source_account": str(goal_ui_context.checking.pk),
                "destination_account": str(goal_ui_context.savings.pk),
                "linked_debt": "",
                "notes": "Synthetic notes",
                "reason": "Synthetic revision",
                "action": "preview",
            },
            "goal.revision_rejected",
            "goal-service-revision",
        ),
        (
            "goals.views.preview_goal",
            reverse("goals:status", args=(goal.pk, GoalRevision.Status.PAUSED)),
            {
                "effective_from": "2026-08-23",
                "status": GoalRevision.Status.PAUSED,
                "reason": "Synthetic status change",
            },
            "goal.status_rejected",
            "goal-service-status",
        ),
        (
            "goals.views.record_goal_contribution",
            reverse("goals:contribute", args=(goal.pk,)),
            {
                "submission_token": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "pay_period": str(goal_ui_context.periods[0].pk),
                "amount": "25.00",
                "effective_date": "2026-08-23",
                "reason": "Synthetic contribution",
            },
            "goal.contribution_rejected",
            "goal-service-contribution",
        ),
        (
            "goals.views.preview_reserve_allocation",
            reverse(
                "goals:reserve-allocate",
                args=(goal.pk, goal_ui_context.periods[0].pk),
            ),
            {"amount": "25.00", "reason": "Synthetic reserve", "action": "preview"},
            "goal.reserve_allocation_rejected",
            "goal-service-reserve",
        ),
        (
            "goals.views.preview_priority_allocation",
            reverse("goals:priority-allocate", args=(goal_ui_context.periods[0].pk,)),
            {"amount": "25.00", "reason": "Synthetic priority", "action": "preview"},
            "goal.priority_allocation_rejected",
            "goal-service-priority",
        ),
    )

    with caplog.at_level(logging.WARNING, logger="security"):
        for target, url, data, _event, request_id in workflows:
            with patch(target, side_effect=ValidationError(canary)):
                response = client.post(
                    url,
                    data,
                    headers={"X-Request-ID": request_id},
                )
            assert response.status_code == 200

    expected_events = [event for _target, _url, _data, event, _request_id in workflows]
    records = [
        record for record in caplog.records if getattr(record, "event", None) in expected_events
    ]
    assert [record.event for record in records] == expected_events  # type: ignore[attr-defined]
    assert [record.error_reference for record in records] == [  # type: ignore[attr-defined]
        request_id for _target, _url, _data, _event, request_id in workflows
    ]
    assert all(canary not in RedactingJsonFormatter().format(record) for record in records)


@pytest.mark.django_db
def test_goal_detail_manual_contribution_revision_and_status_workflows(
    client: Client,
    goal_ui_context: GoalUiContext,
) -> None:
    goal = _service_goal(goal_ui_context, effective_from=date(2026, 8, 20))
    _mfa_ready(goal_ui_context.user)
    client.force_login(goal_ui_context.user)

    detail = client.get(reverse("goals:detail", args=(goal.pk,)))
    assert detail.status_code == 200
    assert b"Actual protected activity" in detail.content
    contribution = client.post(
        reverse("goals:contribute", args=(goal.pk,)),
        {
            "submission_token": "88888888-8888-4888-8888-888888888888",
            "pay_period": str(goal_ui_context.periods[0].pk),
            "amount": "75.00",
            "effective_date": "2026-08-23",
            "reason": "Manual transfer",
        },
    )
    assert contribution.status_code == 302
    assert (
        GoalContribution.objects.get().contribution_type == GoalContribution.ContributionType.MANUAL
    )

    revision_payload = {
        "effective_from": "2026-08-23",
        "name": "Emergency Fund",
        "goal_type": GoalRevision.GoalType.SAVINGS,
        "target_amount": "2500.00",
        "target_date": "2027-08-20",
        "contribution_per_period": "125.00",
        "priority": "2",
        "status": GoalRevision.Status.ACTIVE,
        "source_account": str(goal_ui_context.checking.pk),
        "destination_account": str(goal_ui_context.savings.pk),
        "linked_debt": "",
        "notes": "Revised target",
        "reason": "Increase the emergency cushion",
        "action": "preview",
    }
    preview_response = client.post(reverse("goals:revise", args=(goal.pk,)), revision_payload)
    assert preview_response.status_code == 200
    preview = preview_response.context["preview"]
    revision_payload.update({"action": "confirm", "preview_fingerprint": preview.fingerprint})
    confirmed = client.post(reverse("goals:revise", args=(goal.pk,)), revision_payload)
    assert confirmed.status_code == 302
    assert goal.revisions.order_by("-revision_number").first().target_amount == Decimal("2500.00")

    status_url = reverse("goals:status", args=(goal.pk, GoalRevision.Status.PAUSED))
    assert client.get(status_url).status_code == 200
    paused = client.post(
        status_url,
        {
            "effective_from": "2026-08-24",
            "status": GoalRevision.Status.PAUSED,
            "reason": "Temporary pause",
        },
    )
    assert paused.status_code == 302
    assert goal.revisions.order_by("-revision_number").first().status == GoalRevision.Status.PAUSED


@pytest.mark.django_db
def test_priority_reserve_ui_previews_and_confirms_eligible_goals(
    client: Client,
    goal_ui_context: GoalUiContext,
) -> None:
    first, posting = goal_ui_context.periods[:2]
    close_period(
        pay_period=first,
        actor=goal_ui_context.user,
        closing_surplus=Decimal("250.00"),
        request_id="goal-ui-priority-close",
    )
    _service_goal(
        goal_ui_context,
        effective_from=posting.start_date,
        name="Priority one",
        target="150.00",
        priority=1,
        automatic=True,
    )
    _service_goal(
        goal_ui_context,
        effective_from=posting.start_date,
        name="Priority two",
        target="200.00",
        priority=2,
        automatic=True,
    )
    _mfa_ready(goal_ui_context.user)
    client.force_login(goal_ui_context.user)
    url = reverse("goals:priority-allocate", args=(posting.pk,))
    preview_response = client.post(
        url,
        {"amount": "200.00", "reason": "Apply priorities", "action": "preview"},
    )
    assert preview_response.status_code == 200
    assert b"Priority one" in preview_response.content
    assert b"Priority two" in preview_response.content
    preview = preview_response.context["preview"]
    confirmed = client.post(
        url,
        {
            "amount": "200.00",
            "reason": "Apply priorities",
            "action": "confirm",
            "preview_fingerprint": preview.fingerprint,
        },
    )
    assert confirmed.status_code == 302
    assert reserve_balance(goal_ui_context.household) == Decimal("50.00")
    assert (
        GoalContribution.objects.filter(
            contribution_type=GoalContribution.ContributionType.AUTOMATIC
        ).count()
        == 2
    )
