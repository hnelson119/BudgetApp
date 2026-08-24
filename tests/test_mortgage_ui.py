from __future__ import annotations

from datetime import date
from decimal import Decimal

import pytest
from django.test import Client
from django.urls import reverse

from audit.models import AuditEvent
from debts.models import DebtAccount, DebtTermsRevision, MortgagePaymentPlan
from debts.services import DebtTermsSpec, create_debt_account
from households.models import Household, HouseholdMembership
from identity.models import User
from identity.services.mfa import (
    begin_enrollment,
    confirm_enrollment,
    confirm_recovery_codes_saved,
    totp_code,
)
from periods.models import PayPeriod
from schedules.models import Occurrence

TEST_PASSWORD = "mortgage-ui-test-password"  # pragma: allowlist secret


def _mfa_ready(user: User) -> None:
    enrollment = begin_enrollment(user)
    assert confirm_enrollment(user, totp_code(enrollment.secret)) is not None
    assert confirm_recovery_codes_saved(user) is True
    user.refresh_from_db()


@pytest.fixture
def mortgage_ui_context(db: object) -> tuple[Household, User, User, DebtAccount]:
    household = Household.objects.create(name="Mortgage UI Household")
    user = User.objects.create_user(email="mortgage-ui@example.com", password=TEST_PASSWORD)
    outsider = User.objects.create_user(email="mortgage-hidden@example.com", password=TEST_PASSWORD)
    HouseholdMembership.objects.create(household=household, user=user)
    other_household = Household.objects.create(name="Other Mortgage Household")
    HouseholdMembership.objects.create(household=other_household, user=outsider)
    debt, _ = create_debt_account(
        household=household,
        actor=user,
        name="Home mortgage",
        debt_type=DebtAccount.DebtType.MORTGAGE,
        opening_balance=Decimal("250000.00"),
        terms=DebtTermsSpec(
            effective_from=date(2020, 1, 1),
            annual_percentage_rate=Decimal("5.5000"),
            interest_method=DebtTermsRevision.InterestMethod.MONTHLY,
            day_count_basis=DebtTermsRevision.DayCountBasis.ACTUAL_365,
            minimum_payment=Decimal("1350.00"),
            due_day=20,
        ),
        request_id="mortgage-ui-debt",
    )
    for start, end in (
        (date(2026, 8, 27), date(2026, 9, 3)),
        (date(2026, 9, 3), date(2026, 9, 10)),
        (date(2026, 9, 10), date(2026, 9, 17)),
        (date(2026, 9, 17), date(2026, 9, 24)),
        (date(2026, 9, 24), date(2026, 10, 1)),
        (date(2026, 10, 1), date(2026, 10, 8)),
        (date(2026, 10, 8), date(2026, 10, 15)),
        (date(2026, 10, 15), date(2026, 10, 22)),
        (date(2026, 10, 22), date(2026, 10, 29)),
        (date(2026, 10, 29), date(2026, 11, 5)),
    ):
        PayPeriod.objects.create(
            household=household,
            start_date=start,
            next_start_date=end,
            created_by=user,
        )
    return household, user, outsider, debt


def _payload(*, effective_from: str = "2026-09-01") -> dict[str, str]:
    return {
        "effective_from": effective_from,
        "monthly_obligation": "1350.00",
        "principal_and_interest": "1100.00",
        "escrow": "250.00",
        "pmi": "0.00",
        "fees": "0.00",
        "recurring_extra_principal": "0.00",
        "statement_cycle_day": "20",
        "installment_one_amount": "675.00",
        "installment_one_day": "5",
        "installment_two_amount": "675.00",
        "installment_two_day": "20",
        "adjustment_policy": "previous",
        "reason": "",
    }


def _create_plan_through_ui(client: Client, debt: DebtAccount) -> MortgagePaymentPlan:
    url = reverse("debts:mortgage-plan-create", args=(debt.pk,))
    payload = _payload()
    preview = client.post(url, {**payload, "action": "preview"})
    assert preview.status_code == 200
    assert b"Confirm both schedules" in preview.content
    fingerprint = preview.context["preview"].fingerprint
    confirmed = client.post(
        url,
        {
            **payload,
            "action": "confirm",
            "preview_fingerprint": fingerprint,
        },
    )
    assert confirmed.status_code == 302
    return MortgagePaymentPlan.objects.get(debt=debt)


@pytest.mark.django_db
def test_mortgage_plan_ui_previews_confirms_and_renders_responsive_details(
    client: Client,
    mortgage_ui_context: tuple[Household, User, User, DebtAccount],
) -> None:
    _, user, _, debt = mortgage_ui_context
    _mfa_ready(user)
    client.force_login(user)

    detail_before = client.get(reverse("debts:detail", args=(debt.pk,)))
    assert detail_before.status_code == 200
    assert b"Set up split payments" in detail_before.content
    _create_plan_through_ui(client, debt)

    detail = client.get(reverse("debts:detail", args=(debt.pk,)))
    assert detail.status_code == 200
    assert b"P&amp;I" in detail.content
    assert b"$1,100.00" in detail.content
    assert b"$250.00" in detail.content
    occurrence = Occurrence.objects.get(expected_date=date(2026, 9, 18))
    budget = client.get(reverse("budgets:detail", args=(occurrence.pay_period_id,)))
    assert budget.status_code == 200
    assert b"Extra principal" in budget.content
    assert AuditEvent.objects.filter(action="mortgage.plan_created").exists()


@pytest.mark.django_db
def test_mortgage_ui_rejects_stale_confirmation_and_requires_revision_reason(
    client: Client,
    mortgage_ui_context: tuple[Household, User, User, DebtAccount],
) -> None:
    _, user, _, debt = mortgage_ui_context
    _mfa_ready(user)
    client.force_login(user)
    create_url = reverse("debts:mortgage-plan-create", args=(debt.pk,))
    stale = client.post(
        create_url,
        {**_payload(), "action": "confirm", "preview_fingerprint": "stale"},
    )
    assert stale.status_code == 200
    assert b"preview is stale" in stale.content
    assert not MortgagePaymentPlan.objects.filter(debt=debt).exists()

    plan = _create_plan_through_ui(client, debt)
    revise_url = reverse("debts:mortgage-plan-revise", args=(debt.pk,))
    payload = _payload(effective_from="2026-10-01")
    preview = client.post(revise_url, {**payload, "action": "preview"})
    fingerprint = preview.context["preview"].fingerprint
    rejected = client.post(
        revise_url,
        {**payload, "action": "confirm", "preview_fingerprint": fingerprint},
    )
    assert rejected.status_code == 200
    assert b"requires a reason" in rejected.content
    assert plan.revisions.count() == 1


@pytest.mark.django_db
def test_extra_principal_ui_is_confirmed_scoped_and_one_way(
    client: Client,
    mortgage_ui_context: tuple[Household, User, User, DebtAccount],
) -> None:
    _, user, outsider, debt = mortgage_ui_context
    _mfa_ready(user)
    _mfa_ready(outsider)
    client.force_login(user)
    plan = _create_plan_through_ui(client, debt)
    rule = plan.revisions.get().installment_rules.get(installment_order=2)
    occurrence = rule.source.occurrences.get(expected_date=date(2026, 9, 18))
    future = rule.source.occurrences.get(expected_date=date(2026, 10, 20))
    url = reverse("debts:mortgage-extra-principal", args=(occurrence.pk,))

    unconfirmed = client.post(
        url,
        {"extra_principal": "100.00", "reason": "Use excess"},
    )
    assert unconfirmed.status_code == 200
    occurrence.refresh_from_db()
    assert occurrence.planned_amount == Decimal("675.00")
    saved = client.post(
        url,
        {
            "extra_principal": "100.00",
            "reason": "Use excess",
            "confirm": "on",
        },
    )
    assert saved.status_code == 302
    occurrence.refresh_from_db()
    future.refresh_from_db()
    assert occurrence.planned_amount == Decimal("775.00")
    assert future.planned_amount == Decimal("675.00")
    assert rule.source.revisions.count() == 1

    client.force_login(outsider)
    assert client.get(url).status_code == 404


@pytest.mark.django_db
def test_mortgage_mutation_routes_require_login_and_allowed_methods(
    mortgage_ui_context: tuple[Household, User, User, DebtAccount],
) -> None:
    _, user, _, debt = mortgage_ui_context
    client = Client()
    create_url = reverse("debts:mortgage-plan-create", args=(debt.pk,))
    assert client.get(create_url).status_code == 302

    _mfa_ready(user)
    client.force_login(user)
    assert client.put(create_url, data={}).status_code == 405
