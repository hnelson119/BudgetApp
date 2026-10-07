from __future__ import annotations

from dataclasses import replace
from datetime import date, timedelta
from decimal import Decimal

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.test import Client
from django.urls import reverse
from django.utils import timezone

from audit.services import verify_household_chain
from debts.forms import DebtPromotionForm
from debts.models import DebtPromotionRevision, DebtTermsRevision
from debts.services.planner import payoff_target, preview_payoff_plan
from debts.services.projections import (
    PayoffStrategy,
    ProjectionDebt,
    ProjectionExtraPayment,
    ProjectionPromotion,
    ProjectionTerms,
    project_debt_payoff,
    projection_debts_from_accounts,
)
from debts.services.promotions import (
    PromotionSpec,
    effective_apr,
    promotion_summary,
    save_promotion,
)
from households.models import Household, HouseholdMembership
from ledger.models import JournalEntry
from periods.models import PayPeriod
from schedules.models import Occurrence
from tests.test_debt_ui import _mfa_ready
from tests.test_debt_ui import debt_ui_context as _debt_ui_context

START = date(2026, 1, 1)


@pytest.fixture
def debt_ui_context(db):
    return _debt_ui_context.__wrapped__(db)


def _projection(
    *,
    kind="introductory",
    extras=(),
    expires=date(2026, 1, 15),
    accrued="0.00",
    as_of=START,
    max_months=1,
):
    debt = ProjectionDebt(
        "promo",
        "Promotional debt",
        Decimal("1000.00"),
        (
            ProjectionTerms(
                START,
                Decimal("36.5"),
                DebtTermsRevision.InterestMethod.DAILY,
                DebtTermsRevision.DayCountBasis.ACTUAL_365,
                Decimal("0.00"),
            ),
        ),
        extras,
        ProjectionPromotion(
            kind, as_of, expires, Decimal("0.00"), Decimal("36.5"), Decimal(accrued)
        ),
    )
    return project_debt_payoff(
        (debt,),
        strategy=PayoffStrategy.MINIMUM_ONLY,
        monthly_extra=Decimal("0.00"),
        start_date=START,
        max_months=max_months,
    )


def test_introductory_apr_changes_after_deadline_without_retroactive_interest():
    result = _projection()
    assert result.total_interest == Decimal("16.00")
    assert result.debts[0].deferred_interest == 0


def test_deferred_deadline_adds_recorded_and_estimated_interest_once():
    result = _projection(kind="deferred", accrued="100.00")
    assert result.debts[0].deferred_interest == Decimal("115.00")
    assert result.cycles[0].payments[0].deferred_interest == Decimal("115.00")
    assert result.payment_warnings[0].deferred_interest == Decimal("115.00")
    assert result.total_interest == Decimal("132.84")
    assert result.debts[0].remaining_balance == Decimal("1132.84")


@pytest.mark.parametrize("payment_date", [date(2026, 1, 14), date(2026, 1, 15)])
def test_deferred_full_payment_by_deadline_waives_accrual(payment_date):
    result = _projection(
        kind="deferred",
        accrued="100.00",
        extras=(ProjectionExtraPayment(payment_date, Decimal("1000.00")),),
    )
    assert result.total_interest == 0
    assert result.paid_off
    assert result.debts[0].payoff_date == payment_date


def test_deferred_charge_is_not_repeated_in_following_cycle():
    result = _projection(kind="deferred", accrued="100.00", max_months=2)
    assert result.debts[0].deferred_interest == Decimal("115.00")
    assert result.cycles[1].payments[0].deferred_interest == 0


def test_partial_deadline_payment_keeps_deferred_charge_and_reduces_future_accrual():
    result = _projection(
        kind="deferred",
        accrued="100.00",
        extras=(ProjectionExtraPayment(date(2026, 1, 15), Decimal("500.00")),),
    )
    assert result.debts[0].deferred_interest == Decimal("114.50")
    assert result.total_interest == Decimal("124.33")


def test_expired_deferred_charge_is_not_added_again_to_reconciled_balance():
    result = _projection(
        kind="deferred",
        expires=START - timedelta(days=1),
        as_of=START - timedelta(days=15),
        accrued="100.00",
    )
    assert result.debts[0].deferred_interest == 0
    assert result.total_interest == Decimal("31.00")


def test_daily_rate_changes_and_early_payments_use_actual_dates():
    debt = ProjectionDebt(
        "daily",
        "Daily loan",
        Decimal("1000.00"),
        (
            ProjectionTerms(START, Decimal("36.5"), "daily", "actual_365", Decimal("0.00")),
            ProjectionTerms(
                date(2026, 1, 16), Decimal("73"), "daily", "actual_365", Decimal("0.00")
            ),
        ),
        (ProjectionExtraPayment(date(2026, 1, 16), Decimal("515.00")),),
    )
    result = project_debt_payoff(
        (debt,),
        strategy="minimum_only",
        monthly_extra=Decimal("0.00"),
        start_date=START,
        max_months=1,
    )
    assert result.total_interest == Decimal("31.00")
    assert result.debts[0].remaining_balance == Decimal("516.00")


def _spec(today, kind="deferred"):
    return PromotionSpec(
        kind,
        today,
        today + timedelta(days=20),
        Decimal("0.0000"),
        Decimal("29.9900"),
        Decimal("250.00") if kind == "deferred" else None,
    )


def _save(context, spec, **overrides):
    arguments = dict(
        debt=context.debt,
        actor=context.user,
        spec=spec,
        expected_revision=0,
        expected_balance=context.debt.current_balance,
        confirm_entire_balance=True,
        request_id="promo-save",
    )
    arguments.update(overrides)
    return save_promotion(**arguments)


def test_promotions_are_immutable_audited_and_leave_budget_and_balance_unchanged(debt_ui_context):
    context = debt_ui_context
    today = timezone.localdate()
    original = list(Occurrence.objects.values_list("pk", "planned_amount", "status"))
    promotion = _save(context, _spec(today))
    assert promotion.revision_number == 1
    context.debt.refresh_from_db()
    assert context.debt.current_balance == Decimal("18400.00")
    assert list(Occurrence.objects.values_list("pk", "planned_amount", "status")) == original
    assert not JournalEntry.objects.exists()
    assert verify_household_chain(context.household).valid
    with pytest.raises(ValidationError, match="cannot be updated"):
        promotion.save()
    with pytest.raises(ValidationError, match="changed"):
        _save(context, _spec(today))
    with pytest.raises(PermissionDenied):
        _save(context, _spec(today), actor=context.outsider)
    ended = _save(context, PromotionSpec("none", today), expected_revision=1)
    assert ended.revision_number == 2
    assert projection_debts_from_accounts((context.debt,))[0].promotion is None


@pytest.mark.parametrize("change", ["scope", "date", "accrued", "rate", "future"])
def test_invalid_promotion_terms_reject_before_writes(debt_ui_context, change):
    today = timezone.localdate()
    spec = _spec(today)
    kwargs = {}
    if change == "scope":
        kwargs["confirm_entire_balance"] = False
    elif change == "date":
        spec = replace(spec, expires_on=today - timedelta(days=1))
    elif change == "accrued":
        spec = replace(spec, accrued_interest=None)
    elif change == "rate":
        spec = replace(spec, regular_apr=Decimal("1000.00"))
    else:
        spec = replace(spec, as_of=today + timedelta(days=1))
    with pytest.raises(ValidationError):
        _save(debt_ui_context, spec, **kwargs)
    assert not DebtPromotionRevision.objects.exists()


def test_deadline_targets_count_paycheck_windows_and_round_up(debt_ui_context):
    context = debt_ui_context
    today = timezone.localdate()
    _save(context, _spec(today))
    for offset in (0, 7, 14):
        PayPeriod.objects.create(
            household=context.household,
            start_date=today + timedelta(days=offset),
            next_start_date=today + timedelta(days=offset + 7),
            created_by=context.user,
        )
    summary = promotion_summary(context.debt, today=today)
    assert summary is not None
    assert summary.periods_remaining == 3
    assert summary.total_per_period == Decimal("6133.34")
    assert summary.extra_per_period <= summary.total_per_period
    assert effective_apr(context.debt, on_date=today) == 0
    assert effective_apr(context.debt, on_date=today + timedelta(days=21)) == Decimal("29.9900")
    assert payoff_target(context.household, "avalanche") == context.debt
    assert projection_debts_from_accounts((context.debt,))[0].promotion is not None
    assert (
        preview_payoff_plan(
            household=context.household,
            strategy="avalanche",
            extra_per_period=Decimal("100.00"),
            cash_cushion=Decimal("25.00"),
        )
        .projection.debts[0]
        .deferred_interest
        > 0
    )


def test_deadline_target_includes_nonzero_promotional_interest(debt_ui_context):
    context = debt_ui_context
    today = timezone.localdate()
    _save(context, replace(_spec(today, kind="introductory"), promotional_apr=Decimal("6.5000")))
    for offset in (0, 7, 14):
        PayPeriod.objects.create(
            household=context.household,
            start_date=today + timedelta(days=offset),
            next_start_date=today + timedelta(days=offset + 7),
            created_by=context.user,
        )
    summary = promotion_summary(context.debt, today=today)
    assert summary is not None
    assert summary.estimated_interest_before_deadline == Decimal("68.81")
    assert summary.total_per_period == Decimal("6156.27")


def test_promotion_form_save_history_and_household_csrf_boundaries(debt_ui_context):
    context = debt_ui_context
    _mfa_ready(context.user)
    client = Client()
    client.force_login(context.user)
    url = reverse("debts:promotion", args=(context.debt.pk,))
    page = client.get(url)
    assert page.status_code == 200
    payload = dict(
        kind="deferred",
        as_of=timezone.localdate().isoformat(),
        expires_on=(timezone.localdate() + timedelta(days=20)).isoformat(),
        promotional_apr="0.00",
        regular_apr="29.99",
        accrued_interest="250.00",
        confirm_entire_balance="on",
        confirm="on",
        expected_revision="0",
        expected_balance="18400.00",
    )
    response = client.post(url, payload)
    assert response.status_code == 302
    assert b"Lender-reported deferred interest" in client.get(response.url).content
    assert b"Promotion deadlines" in client.get(reverse("debts:list")).content
    assert b"changed" in client.post(url, payload).content
    csrf = Client(enforce_csrf_checks=True)
    csrf.force_login(context.user)
    assert csrf.post(url, payload).status_code == 403
    assert client.put(url, payload).status_code == 405
    foreign = Household.objects.create(name="Other promotion household")
    HouseholdMembership.objects.create(household=foreign, user=context.outsider)
    _mfa_ready(context.outsider)
    client.force_login(context.outsider)
    assert client.get(url).status_code == 404
    assert client.post(url, payload).status_code == 404
    incomplete = DebtPromotionForm(dict(payload, accrued_interest=""), household=context.household)
    assert not incomplete.is_valid()
