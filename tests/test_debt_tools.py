from __future__ import annotations

from dataclasses import replace
from datetime import date, timedelta
from decimal import Decimal
from unittest.mock import patch

import pytest
from django.core.exceptions import ValidationError
from django.test import Client
from django.urls import reverse
from django.utils import timezone

from audit.models import AuditEvent
from debts.models import DebtAccount, DebtTermsRevision
from debts.services.accounts import (
    DebtStatementSpec,
    DebtTermsSpec,
    change_debt_status,
    reconcile_debt_statement,
    revise_debt_terms,
)
from debts.services.projections import (
    PayoffStrategy,
    ProjectionDebt,
    ProjectionTerms,
    project_debt_payoff,
)
from debts.services.tools import OfferSpec, compare_offer, debt_progress, solve_payoff_target
from households.models import Household, HouseholdMembership
from ledger.models import JournalEntry
from periods.models import PayPeriod
from schedules.models import Occurrence
from tests.test_debt_ui import _mfa_ready
from tests.test_debt_ui import debt_ui_context as _debt_ui_context

START = date(2026, 1, 1)
ZERO = Decimal("0.00")


@pytest.fixture
def debt_ui_context(db):
    return _debt_ui_context.__wrapped__(db)


def _debt(apr="0", balance="1000.00", payment="100.00"):
    return ProjectionDebt(
        "test",
        "Test debt",
        Decimal(balance),
        (
            ProjectionTerms(
                START,
                Decimal(apr),
                DebtTermsRevision.InterestMethod.MONTHLY,
                DebtTermsRevision.DayCountBasis.ACTUAL_365,
                Decimal(payment),
            ),
        ),
    )


def _target(**kwargs):
    values = {
        "debts": (_debt(),),
        "start_date": START,
        "target_date": date(2026, 3, 1),
        "strategy": "avalanche",
        "average_days": Decimal("7"),
        "maximum_extra": Decimal("500.00"),
    }
    values.update(kwargs)
    return solve_payoff_target(**values)


@pytest.mark.parametrize("strategy", ("snowball", "avalanche", "custom"))
def test_target_search_reaches_deadline_at_lowest_cent(strategy):
    result = _target(strategy=strategy)
    assert result.required_extra == Decimal("92.06")
    assert result.projection.paid_off
    assert result.projection.payoff_date == date(2026, 3, 1)
    smaller = project_debt_payoff(
        (_debt(),),
        strategy=PayoffStrategy(strategy),
        monthly_extra=((result.required_extra - Decimal("0.01")) * 365 / 84).quantize(
            Decimal("0.01")
        ),
        start_date=START,
        max_months=2,
    )
    assert not smaller.paid_off


def test_target_current_payments_suffice_and_ceiling_can_be_unreachable():
    assert _target(target_date=date(2026, 11, 1)).required_extra == ZERO
    result = _target(maximum_extra=Decimal("10.00"))
    assert result.required_extra is None
    assert not result.projection.paid_off
    assert result.projection.debts[0].remaining_balance > 0


@pytest.mark.parametrize(
    "values",
    (
        {"target_date": date(2026, 1, 20)},
        {"target_date": date(2036, 2, 1)},
        {"average_days": ZERO},
        {"debts": ()},
        {"maximum_extra": Decimal("NaN")},
        {"maximum_extra": Decimal("1000000.01")},
        {"strategy": "minimum_only"},
    ),
)
def test_target_rejects_invalid_and_unbounded_requests(values):
    with pytest.raises(ValidationError):
        _target(**values)


def _offer(**kwargs):
    spec = OfferSpec(Decimal("0"), Decimal("100.00"), Decimal("3"), ZERO, True)
    return compare_offer(_debt(apr="24"), start_date=START, spec=replace(spec, **kwargs))


def test_offer_financed_fee_is_counted_once_and_break_even_is_supported():
    result = _offer()
    assert result.fees == Decimal("30.00")
    assert result.financed_balance == Decimal("1030.00")
    assert result.offer.total_paid == Decimal("1030.00")
    assert result.offer_cost == Decimal("30.00")
    assert result.savings == result.baseline.total_interest - Decimal("30.00")
    assert result.break_even_date is not None


def test_upfront_fee_is_not_financed_and_financed_fees_accrue_interest():
    upfront = _offer(finance_fees=False, fixed_fee=Decimal("20.00"))
    financed = _offer(annual_percentage_rate=Decimal("12"), fixed_fee=Decimal("20.00"))
    assert upfront.financed_balance == Decimal("1000.00")
    assert upfront.fees == Decimal("50.00")
    assert financed.financed_balance == Decimal("1050.00")
    assert financed.offer_cost == financed.offer.total_interest + Decimal("50.00")


def test_low_payment_extends_payoff_and_unfinished_paths_have_no_savings_claim():
    assert _offer(monthly_payment=Decimal("25.00"), fee_percent=ZERO).longer_payoff
    incomplete = _offer(monthly_payment=Decimal("1.00"), maximum_months=12)
    assert incomplete.savings is None
    assert incomplete.break_even_date is None
    assert not incomplete.offer.paid_off


def test_zero_apr_transfer_fees_can_make_offer_more_expensive():
    result = compare_offer(
        _debt(),
        start_date=START,
        spec=OfferSpec(ZERO, Decimal("100.00"), Decimal("10"), ZERO, True),
    )
    assert result.savings == Decimal("-100.00")
    assert result.break_even_date is None


def test_temporary_offer_uses_post_promotion_rate():
    result = _offer(expires_on=date(2026, 1, 15), regular_apr=Decimal("24"))
    assert result.offer.cycles[0].payments[0].interest > 0
    assert result.offer.total_interest > 0


def test_early_cost_recovery_is_not_claimed_when_later_costs_reverse_it():
    debt = replace(
        _debt(apr="120"),
        terms=(
            _debt(apr="120").terms[0],
            replace(_debt().terms[0], effective_from=date(2026, 2, 1)),
        ),
    )
    spec = OfferSpec(Decimal("12"), Decimal("100.00"), ZERO, Decimal("70.00"), False)
    result = compare_offer(debt, start_date=START, spec=spec)
    assert (
        result.baseline.cycles[0].payments[0].interest
        > result.offer.cycles[0].payments[0].interest + result.fees
    )
    assert result.savings < 0
    assert result.break_even_date is None


@pytest.mark.parametrize(
    "values",
    (
        {"expires_on": date(2026, 2, 1)},
        {"regular_apr": Decimal("24")},
        {"expires_on": date(2025, 12, 31), "regular_apr": Decimal("24")},
        {"annual_percentage_rate": Decimal("1000")},
        {"monthly_payment": ZERO},
        {"maximum_months": 481},
        {"fee_percent": Decimal("NaN")},
    ),
)
def test_offer_rejects_incomplete_or_unbounded_terms(values):
    with pytest.raises(ValidationError):
        _offer(**values)


def test_progress_replaces_corrected_components_and_does_not_count_archival_as_payoff(
    debt_ui_context,
):
    context = debt_ui_context
    today = timezone.localdate()
    spec = DebtStatementSpec(
        today - timedelta(days=50),
        Decimal("18000.00"),
        Decimal("7.25"),
        Decimal("225.00"),
        principal_paid=Decimal("300.00"),
        extra_principal_paid=Decimal("100.00"),
        interest_charged=Decimal("90.00"),
        fees_charged=Decimal("5.00"),
    )
    original = reconcile_debt_statement(
        debt=context.debt, actor=context.user, statement=spec, request_id="tools-statement"
    )
    reconcile_debt_statement(
        debt=context.debt,
        actor=context.user,
        statement=replace(spec, principal_paid=Decimal("350.00")),
        supersedes=original,
        reason="Correct lender figure",
        request_id="tools-correction",
    )
    row = debt_progress(context.household, today=today)[0]
    assert row.principal_paid == Decimal("450.00")
    assert row.interest_charged == Decimal("90.00")
    assert row.fees_charged == Decimal("5.00")
    assert row.statement_count == 1
    assert row.stale_statement
    change_debt_status(
        debt=context.debt,
        actor=context.user,
        status=DebtAccount.Status.ARCHIVED,
        reason="Pause",
        request_id="tools-archive",
    )
    archived = debt_progress(context.household, today=today)[0]
    assert not archived.paid_off
    assert not archived.stale_statement
    foreign = Household.objects.create(name="Unrelated household")
    assert debt_progress(foreign, today=today) == ()


def test_calculator_views_are_read_only_scoped_and_share_expensive_budget(
    debt_ui_context, settings
):
    context = debt_ui_context
    _mfa_ready(context.user)
    client = Client()
    client.force_login(context.user)
    today = timezone.localdate()
    PayPeriod.objects.create(
        household=context.household,
        start_date=today,
        next_start_date=today + timedelta(days=7),
        created_by=context.user,
    )
    paths = [reverse("debts:payoff-target"), reverse("debts:offer", args=[context.debt.pk])]
    initial = (
        Occurrence.objects.count(),
        JournalEntry.objects.count(),
        context.debt.current_balance,
    )
    for path in paths:
        assert client.get(path).status_code == 200
        assert client.post(path).status_code == 405
    target = client.get(
        paths[0],
        {
            "strategy": "avalanche",
            "target_date": (today + timedelta(days=365)).isoformat(),
            "maximum_extra": "500.00",
        },
    )
    assert target.status_code == 200
    assert target.context["result"] is not None
    payload = {
        "annual_percentage_rate": "0",
        "monthly_payment": "500",
        "fee_percent": "3",
        "fixed_fee": "0",
        "finance_fees": "on",
        "maximum_months": "120",
    }
    offer = client.get(paths[1], payload)
    assert offer.status_code == 200
    assert offer.context["result"] is not None
    assert client.get(reverse("debts:list")).context["progress_rows"][0].stale_statement
    context.debt.refresh_from_db()
    assert initial == (
        Occurrence.objects.count(),
        JournalEntry.objects.count(),
        context.debt.current_balance,
    )
    settings.EXPENSIVE_CALCULATION_RATE_LIMIT = 2
    assert client.get(paths[1], payload).status_code == 429
    _mfa_ready(context.outsider)
    foreign = Household.objects.create(name="Other")
    HouseholdMembership.objects.create(household=foreign, user=context.outsider)
    outsider = Client()
    outsider.force_login(context.outsider)
    assert outsider.get(paths[1]).status_code == 404
    assert outsider.get(paths[1], payload).status_code == 404
    assert (
        outsider.get(
            paths[0],
            {
                "strategy": "avalanche",
                "target_date": (today + timedelta(days=365)).isoformat(),
                "maximum_extra": "500.00",
            },
        )
        .context["form"]
        .non_field_errors()
    )


@pytest.mark.parametrize(
    "balance,milestone",
    (
        ("4600.00", "Balance down at least 75%"),
        ("9200.00", "Balance down at least 50%"),
        ("13800.00", "Balance down at least 25%"),
        ("19000.00", "Balance increased since added"),
        ("0.00", "Balance cleared"),
    ),
)
def test_progress_milestones_and_low_payment_alert_use_recorded_balance(
    debt_ui_context, balance, milestone
):
    context = debt_ui_context
    today = timezone.localdate()
    revise_debt_terms(
        debt=context.debt,
        actor=context.user,
        terms=DebtTermsSpec(
            today,
            Decimal("7.25"),
            DebtTermsRevision.InterestMethod.MONTHLY,
            DebtTermsRevision.DayCountBasis.ACTUAL_365,
            ZERO,
        ),
        request_id="tools-low-payment",
        reason="Test a payment that does not reduce principal",
    )
    reconcile_debt_statement(
        debt=context.debt,
        actor=context.user,
        statement=DebtStatementSpec(today, Decimal(balance), Decimal("7.25"), ZERO),
        request_id="tools-milestone",
    )
    row = debt_progress(context.household, today=today)[0]
    assert row.milestone == milestone
    assert row.net_reduction == Decimal("18400.00") - Decimal(balance)
    assert row.paid_off == (Decimal(balance) == 0)
    assert not row.stale_statement
    assert row.payment_warning == (Decimal(balance) > 0)


def test_missing_opening_history_is_unavailable_rather_than_invented(debt_ui_context):
    context = debt_ui_context
    with patch(
        "debts.services.tools.AuditEvent.objects.filter", return_value=AuditEvent.objects.none()
    ):
        row = debt_progress(context.household, today=timezone.localdate())[0]
    assert row.net_reduction is None
    assert row.milestone == "Building progress"
