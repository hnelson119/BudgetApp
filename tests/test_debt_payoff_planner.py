from __future__ import annotations

from datetime import date
from decimal import Decimal

import pytest
from django.core.exceptions import PermissionDenied, ValidationError
from django.test import Client
from django.urls import reverse
from django.utils import timezone

from audit.services import verify_household_chain
from debts.models import DebtAccount, DebtPayoffAllocation, DebtPayoffPlan, DebtTermsRevision
from debts.services import (
    DebtStatementSpec,
    DebtTermsSpec,
    change_debt_status,
    create_debt_account,
    reconcile_debt_statement,
    revise_debt_terms,
)
from debts.services.planner import (
    apply_payoff_payment,
    payoff_target,
    preview_payoff_payment,
    preview_payoff_plan,
    save_payoff_plan,
)
from households.models import Household, HouseholdMembership
from identity.models import User
from identity.services.mfa import (
    begin_enrollment,
    confirm_enrollment,
    confirm_recovery_codes_saved,
    totp_code,
)
from ledger.models import JournalEntry
from periods.models import PayPeriod
from schedules.models import Occurrence, RecurringSource
from schedules.recurrence import Frequency, RecurrenceRule
from schedules.services import (
    RevisionSpec,
    create_recurring_source,
    override_occurrence,
    preview_revision,
    synchronize_occurrences,
)

TODAY = date(2026, 10, 6)


@pytest.fixture
def planner_context(
    db: object, monkeypatch: pytest.MonkeyPatch
) -> tuple[Household, User, PayPeriod, DebtAccount, DebtAccount]:
    monkeypatch.setattr(timezone, "localdate", lambda **kwargs: TODAY)
    household = Household.objects.create(name="Planner household")
    actor = User.objects.create_user(email="payoff-planner@example.com")
    HouseholdMembership.objects.create(household=household, user=actor)
    periods = []
    for start, end in (
        (date(2026, 10, 8), date(2026, 10, 15)),
        (date(2026, 10, 15), date(2026, 10, 22)),
    ):
        period = PayPeriod.objects.create(
            household=household, start_date=start, next_start_date=end, created_by=actor
        )
        periods.append(period)
        spec = RevisionSpec(
            effective_from=TODAY,
            expected_amount=Decimal("300.00"),
            rule=RecurrenceRule(Frequency.ONCE, start),
        )
        create_recurring_source(
            household=household,
            actor=actor,
            kind=RecurringSource.Kind.INCOME,
            name=f"Paycheck {start}",
            revision_spec=spec,
            expected_preview_fingerprint=preview_revision(spec, preview_from=TODAY).fingerprint,
            request_id="planner-income",
        )
    debts = []
    for name, balance, apr, day in (
        ("High APR", "1000.00", "25.0000", 20),
        ("Small balance", "500.00", "15.0000", 13),
    ):
        debt, _ = create_debt_account(
            household=household,
            actor=actor,
            name=name,
            debt_type=DebtAccount.DebtType.CREDIT_CARD,
            opening_balance=Decimal(balance),
            terms=DebtTermsSpec(
                effective_from=TODAY,
                annual_percentage_rate=Decimal(apr),
                interest_method=DebtTermsRevision.InterestMethod.MONTHLY,
                day_count_basis=DebtTermsRevision.DayCountBasis.ACTUAL_365,
                minimum_payment=Decimal("50.00"),
                due_day=day,
            ),
            request_id="planner-debt",
        )
        debts.append(debt)
    synchronize_occurrences(
        household=household,
        actor=actor,
        window_start=periods[0].start_date,
        window_end=periods[-1].display_end_date,
        request_id="planner-sync",
    )
    return household, actor, periods[0], debts[0], debts[1]


def _save(
    household: Household,
    actor: User,
    *,
    extra: str = "100.00",
    cushion: str = "25.00",
    strategy: str = "avalanche",
) -> DebtPayoffPlan:
    values = {
        "household": household,
        "strategy": strategy,
        "extra_per_period": Decimal(extra),
        "cash_cushion": Decimal(cushion),
    }
    preview = preview_payoff_plan(**values)
    return save_payoff_plan(
        **values, actor=actor, expected_fingerprint=preview.fingerprint, request_id="planner-save"
    )


def test_plan_preview_and_save_are_immutable_audited_and_do_not_change_budget(
    planner_context,
) -> None:
    household, actor, _period, high, small = planner_context
    original = list(Occurrence.objects.values_list("pk", "planned_amount", "status"))
    plan = _save(household, actor)
    assert plan.revision_number == 1
    assert plan.snapshot_fingerprint.startswith("sha256$")
    assert plan.forecast["payoff_date"] is not None
    assert list(Occurrence.objects.values_list("pk", "planned_amount", "status")) == original
    assert payoff_target(household, "avalanche") == high
    assert payoff_target(household, "snowball") == small
    revised = _save(household, actor, extra="125.00")
    assert revised.revision_number == 2
    plan.refresh_from_db()
    assert plan.extra_per_period == Decimal("100.00")
    with pytest.raises(ValidationError, match="cannot be updated"):
        plan.save()
    with pytest.raises(ValidationError, match="must use a debt service"):
        DebtPayoffPlan.objects.filter(pk=plan.pk).update(extra_per_period=0)
    assert verify_household_chain(household).valid
    assert not JournalEntry.objects.exists()


def test_apply_creates_only_one_period_extra_and_never_posts_or_changes_balances(
    planner_context,
) -> None:
    household, actor, period, high, _ = planner_context
    _save(household, actor)
    preview = preview_payoff_payment(household=household, period=period)
    assert preview.debt == high
    assert preview.amount == Decimal("100.00")
    allocation = apply_payoff_payment(
        household=household,
        period=period,
        actor=actor,
        expected_fingerprint=preview.fingerprint,
        request_id="planner-apply",
    )
    assert allocation.occurrence.pay_period == period
    assert allocation.occurrence.planned_amount == Decimal("100.00")
    assert allocation.debt == high
    high.refresh_from_db()
    assert high.current_balance == Decimal("1000.00")
    assert not JournalEntry.objects.exists()
    with pytest.raises(ValidationError, match="already planned"):
        apply_payoff_payment(
            household=household,
            period=period,
            actor=actor,
            expected_fingerprint=preview.fingerprint,
            request_id="planner-replay",
        )
    assert DebtPayoffAllocation.objects.count() == 1
    assert verify_household_chain(household).valid


def test_future_period_target_uses_terms_effective_on_its_payment_date(planner_context) -> None:
    household, actor, period, high, small = planner_context
    revise_debt_terms(
        debt=high,
        actor=actor,
        terms=DebtTermsSpec(
            effective_from=period.next_start_date,
            annual_percentage_rate=Decimal("0.0000"),
            interest_method=DebtTermsRevision.InterestMethod.MONTHLY,
            day_count_basis=DebtTermsRevision.DayCountBasis.ACTUAL_365,
            minimum_payment=Decimal("50.00"),
            due_day=20,
        ),
        reason="Future lender rate change",
        request_id="planner-future-rate",
    )
    _save(household, actor)
    assert preview_payoff_payment(household=household, period=period).debt == high
    following = PayPeriod.objects.get(household=household, start_date=period.next_start_date)
    assert preview_payoff_payment(household=household, period=following).debt == small


def test_future_extra_reserves_earlier_planned_payments_against_remaining_balance(
    planner_context,
) -> None:
    household, actor, period, high, _ = planner_context
    reconcile_debt_statement(
        debt=high,
        actor=actor,
        statement=DebtStatementSpec(
            statement_date=TODAY,
            statement_balance=Decimal("125.00"),
            annual_percentage_rate=Decimal("25.0000"),
            minimum_payment=Decimal("50.00"),
        ),
        request_id="planner-small-target",
    )
    _save(household, actor)
    preview = preview_payoff_payment(household=household, period=period)
    apply_payoff_payment(
        household=household,
        actor=actor,
        period=period,
        expected_fingerprint=preview.fingerprint,
        request_id="planner-first-extra",
    )
    following = PayPeriod.objects.get(household=household, start_date=period.next_start_date)
    assert preview_payoff_payment(household=household, period=following).amount == 0


def test_payment_caps_cushion_and_future_period_deficits(planner_context) -> None:
    household, actor, period, _, _ = planner_context
    _save(household, actor, extra="500.00", cushion="100.00")
    future_income = Occurrence.objects.get(
        source__kind=RecurringSource.Kind.INCOME, pay_period__start_date=date(2026, 10, 15)
    )
    override_occurrence(
        occurrence=future_income,
        actor=actor,
        planned_amount=Decimal("0.00"),
        reason="Upcoming unpaid period",
        request_id="planner-future-deficit",
    )
    preview = preview_payoff_payment(household=household, period=period)
    assert preview.available == Decimal(
        "100.00"
    )  # 250 now, less 50 future deficit, less 100 cushion.
    assert preview.amount == Decimal("100.00")


def test_stale_payment_and_plan_previews_roll_back_all_writes(planner_context) -> None:
    household, actor, period, _, _ = planner_context
    plan_preview = preview_payoff_plan(
        household=household,
        strategy="avalanche",
        extra_per_period=Decimal("100.00"),
        cash_cushion=Decimal("25.00"),
    )
    _save(household, actor)
    with pytest.raises(ValidationError, match="Preview the plan again"):
        save_payoff_plan(
            household=household,
            actor=actor,
            strategy="avalanche",
            extra_per_period=Decimal("100.00"),
            cash_cushion=Decimal("25.00"),
            expected_fingerprint=plan_preview.fingerprint,
            request_id="planner-old-save",
        )
    payment_preview = preview_payoff_payment(household=household, period=period)
    income = period.occurrences.get(source__kind=RecurringSource.Kind.INCOME)
    override_occurrence(
        occurrence=income,
        actor=actor,
        planned_amount=Decimal("180.00"),
        reason="Paycheck changed",
        request_id="planner-income-change",
    )
    before = (RecurringSource.objects.count(), Occurrence.objects.count())
    with pytest.raises(ValidationError, match="Preview the extra payment again"):
        apply_payoff_payment(
            household=household,
            period=period,
            actor=actor,
            expected_fingerprint=payment_preview.fingerprint,
            request_id="planner-old-apply",
        )
    assert before == (RecurringSource.objects.count(), Occurrence.objects.count())
    assert not DebtPayoffAllocation.objects.exists()


@pytest.mark.parametrize("status", [PayPeriod.Status.CLOSED, PayPeriod.Status.CLOSING_REVIEW])
def test_protected_periods_cannot_receive_extra_allocations(planner_context, status) -> None:
    household, actor, period, _, _ = planner_context
    _save(household, actor)
    period.status = status
    period.save()
    with pytest.raises(ValidationError, match="editable paycheck period"):
        preview_payoff_payment(household=household, period=period)
    assert not DebtPayoffAllocation.objects.exists()


def test_paid_off_payment_rollover_is_budget_capped_and_archive_is_not_payoff(
    planner_context,
) -> None:
    household, actor, period, high, small = planner_context
    _save(household, actor)
    change_debt_status(
        debt=small,
        actor=actor,
        status=DebtAccount.Status.ARCHIVED,
        reason="Stop tracking",
        request_id="planner-archive",
    )
    assert preview_payoff_payment(household=household, period=period).rollover_extra == 0
    change_debt_status(
        debt=small,
        actor=actor,
        status=DebtAccount.Status.ACTIVE,
        reason="Resume tracking",
        request_id="planner-unarchive",
    )
    reconcile_debt_statement(
        debt=small,
        actor=actor,
        statement=DebtStatementSpec(
            statement_date=TODAY,
            statement_balance=Decimal("0.00"),
            annual_percentage_rate=Decimal("15.0000"),
            minimum_payment=Decimal("0.00"),
        ),
        request_id="planner-paid-off",
    )
    preview = preview_payoff_payment(household=household, period=period)
    assert preview.debt == high
    assert preview.rollover_extra == Decimal("11.51")
    assert preview.amount == Decimal("111.51")
    change_debt_status(
        debt=small,
        actor=actor,
        status=DebtAccount.Status.ARCHIVED,
        reason="Archive the paid-off account",
        request_id="planner-archive-paid-off",
    )
    assert preview_payoff_payment(household=household, period=period).rollover_extra == Decimal(
        "11.51"
    )


def test_archiving_target_supersedes_unpaid_extra_without_recreating_it(planner_context) -> None:
    household, actor, period, high, _ = planner_context
    _save(household, actor)
    preview = preview_payoff_payment(household=household, period=period)
    allocation = apply_payoff_payment(
        household=household,
        period=period,
        actor=actor,
        expected_fingerprint=preview.fingerprint,
        request_id="planner-apply-archive",
    )
    change_debt_status(
        debt=high,
        actor=actor,
        status=DebtAccount.Status.ARCHIVED,
        reason="Archive target",
        request_id="planner-stop-extra",
    )
    allocation.occurrence.refresh_from_db()
    assert allocation.occurrence.status == Occurrence.Status.SUPERSEDED
    assert not JournalEntry.objects.exists()


def test_ui_plan_preview_save_apply_scoping_csrf_and_methods(planner_context) -> None:
    household, actor, period, _, _ = planner_context
    enrollment = begin_enrollment(actor)
    assert confirm_enrollment(actor, totp_code(enrollment.secret)) is not None
    assert confirm_recovery_codes_saved(actor)
    actor.refresh_from_db()
    client = Client()
    client.force_login(actor)
    plan_url = reverse("debts:payoff-plan")
    values = {
        "strategy": "avalanche",
        "extra_per_period": "100.00",
        "cash_cushion": "25.00",
        "action": "preview",
    }
    response = client.post(plan_url, values)
    assert response.status_code == 200
    assert response.context["preview"] is not None
    token = response.context["preview"].fingerprint
    assert (
        client.post(plan_url, values | {"action": "save", "preview_fingerprint": token}).status_code
        == 302
    )
    payment_url = reverse("debts:payoff-period", args=(period.pk,))
    response = client.get(payment_url)
    token = response.context["preview"].fingerprint
    assert "High APR" in response.content.decode()
    assert (
        client.post(payment_url, {"preview_fingerprint": token, "confirm": "on"}).status_code == 302
    )
    assert client.get(reverse("debts:list")).status_code == 200
    assert client.put(plan_url).status_code == 405
    csrf = Client(enforce_csrf_checks=True)
    csrf.force_login(actor)
    assert csrf.post(plan_url, values).status_code == 403
    assert csrf.post(payment_url, {}).status_code == 403
    foreign_household = Household.objects.create(name="Foreign planner household")
    foreign_period = PayPeriod.objects.create(
        household=foreign_household,
        start_date=date(2026, 10, 8),
        next_start_date=date(2026, 10, 15),
        created_by=actor,
    )
    assert client.get(reverse("debts:payoff-period", args=(foreign_period.pk,))).status_code == 404
    assert (
        client.post(
            reverse("debts:payoff-period", args=(foreign_period.pk,)), {"confirm": "on"}
        ).status_code
        == 404
    )
    outsider = User.objects.create_user(email="planner-outsider@example.com")
    with pytest.raises(PermissionDenied):
        save_payoff_plan(
            household=household,
            actor=outsider,
            strategy="avalanche",
            extra_per_period=Decimal("100.00"),
            cash_cushion=Decimal("25.00"),
            expected_fingerprint=token,
            request_id="planner-outsider",
        )
