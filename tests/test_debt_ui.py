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
from debts.models import DebtAccount, DebtStatement, DebtTermsRevision
from debts.services import DebtTermsSpec, create_debt_account
from households.models import Household, HouseholdMembership
from identity.models import User
from identity.services.mfa import (
    begin_enrollment,
    confirm_enrollment,
    confirm_recovery_codes_saved,
    totp_code,
)
from ledger.models import FinancialAccount
from ledger.services import create_financial_account

TEST_PASSWORD = "debt-ui-test-password"  # pragma: allowlist secret


@dataclass(frozen=True, slots=True)
class DebtUiContext:
    household: Household
    user: User
    outsider: User
    liability: FinancialAccount
    debt: DebtAccount


def _mfa_ready(user: User) -> None:
    enrollment = begin_enrollment(user)
    assert confirm_enrollment(user, totp_code(enrollment.secret)) is not None
    assert confirm_recovery_codes_saved(user) is True
    user.refresh_from_db()


def _terms(*, minimum: str = "225.00", priority: int = 20) -> DebtTermsSpec:
    return DebtTermsSpec(
        effective_from=date(2020, 1, 1),
        annual_percentage_rate=Decimal("7.2500"),
        interest_method=DebtTermsRevision.InterestMethod.MONTHLY,
        day_count_basis=DebtTermsRevision.DayCountBasis.ACTUAL_365,
        minimum_payment=Decimal(minimum),
        recurring_extra_payment=Decimal("25.00"),
        due_day=15,
        custom_priority=priority,
    )


@pytest.fixture
def debt_ui_context(db: object) -> DebtUiContext:
    household = Household.objects.create(name="Nelson Household")
    user = User.objects.create_user(email="member@example.com", password=TEST_PASSWORD)
    outsider = User.objects.create_user(email="outsider@example.com", password=TEST_PASSWORD)
    HouseholdMembership.objects.create(household=household, user=user)
    liability = create_financial_account(
        household=household,
        actor=user,
        name="Vehicle lender",
        account_type=FinancialAccount.AccountType.OTHER,
        classification=FinancialAccount.Classification.LIABILITY,
        last_four="2040",
        request_id="debt-ui-liability",
    )
    debt, _ = create_debt_account(
        household=household,
        actor=user,
        name="Family SUV",
        debt_type=DebtAccount.DebtType.AUTO_LOAN,
        opening_balance=Decimal("18400.00"),
        terms=_terms(),
        financial_account=liability,
        request_id="debt-ui-account",
    )
    return DebtUiContext(household, user, outsider, liability, debt)


def _create_payload(account: FinancialAccount) -> dict[str, str]:
    return {
        "name": "Student loan",
        "debt_type": DebtAccount.DebtType.STUDENT_LOAN,
        "financial_account": str(account.pk),
        "opening_balance": "9200.00",
        "effective_from": "2020-01-01",
        "annual_percentage_rate": "4.5000",
        "interest_method": DebtTermsRevision.InterestMethod.MONTHLY,
        "day_count_basis": DebtTermsRevision.DayCountBasis.ACTUAL_365,
        "minimum_payment": "125.00",
        "recurring_extra_payment": "10.00",
        "due_day": "8",
        "custom_priority": "10",
        "projection_notes": "Federal repayment terms",
        "notes": "Manual lender data only",
    }


def _statement_payload(*, balance: str = "17910.20") -> dict[str, str]:
    return {
        "statement_date": "2026-08-01",
        "period_start": "2026-07-01",
        "period_end": "2026-07-31",
        "due_date": "2026-08-15",
        "statement_balance": balance,
        "annual_percentage_rate": "7.2500",
        "minimum_payment": "225.00",
        "principal_paid": "171.40",
        "interest_charged": "103.60",
        "fees_charged": "0.00",
        "escrow_paid": "0.00",
        "pmi_paid": "0.00",
        "extra_principal_paid": "50.00",
        "notes": "Entered from August statement",
    }


@pytest.mark.django_db
def test_debt_pages_require_login(client: Client) -> None:
    for url in (
        reverse("debts:list"),
        reverse("debts:create"),
        reverse("debts:payoff-comparison"),
    ):
        response = client.get(url)
        assert response.status_code == 302
        assert response.headers["Location"].startswith(reverse("identity:login"))


@pytest.mark.django_db
def test_debt_mutations_require_csrf_and_allowed_methods(
    debt_ui_context: DebtUiContext,
) -> None:
    _mfa_ready(debt_ui_context.user)
    csrf_client = Client(enforce_csrf_checks=True)
    csrf_client.force_login(debt_ui_context.user)
    rejected = csrf_client.post(
        reverse("debts:status", args=(debt_ui_context.debt.pk, "archive")),
        {"reason": "No longer tracked", "confirm": "on"},
    )
    assert rejected.status_code == 403
    debt_ui_context.debt.refresh_from_db()
    assert debt_ui_context.debt.status == DebtAccount.Status.ACTIVE

    method_client = Client()
    method_client.force_login(debt_ui_context.user)
    assert method_client.put(reverse("debts:create"), data={}).status_code == 405
    assert method_client.post(reverse("debts:list"), data={}).status_code == 405
    assert method_client.post(reverse("debts:payoff-comparison"), data={}).status_code == 405


@pytest.mark.django_db
def test_debt_create_edit_and_terms_revision_are_scoped_and_audited(
    client: Client,
    debt_ui_context: DebtUiContext,
) -> None:
    second_liability = create_financial_account(
        household=debt_ui_context.household,
        actor=debt_ui_context.user,
        name="Student lender",
        account_type=FinancialAccount.AccountType.OTHER,
        classification=FinancialAccount.Classification.LIABILITY,
        request_id="debt-ui-student-liability",
    )
    _mfa_ready(debt_ui_context.user)
    client.force_login(debt_ui_context.user)

    list_response = client.get(reverse("debts:list"))
    assert list_response.status_code == 200
    assert b"Family SUV" in list_response.content
    assert b'class="mobile-nav"' in list_response.content
    assert b"Manual reconciled principal or statement balances" in list_response.content
    assert list_response.headers["Cache-Control"] == "no-store, private"

    created_response = client.post(reverse("debts:create"), _create_payload(second_liability))
    assert created_response.status_code == 302
    created = DebtAccount.objects.get(name="Student loan")
    assert created.financial_account == second_liability
    assert created.terms_revisions.get().minimum_payment == Decimal("125.00")
    assert AuditEvent.objects.filter(
        action="debt.account_created", entity_id=str(created.pk)
    ).exists()

    edited_response = client.post(
        reverse("debts:edit", args=(created.pk,)),
        {
            "name": "Federal student loan",
            "debt_type": DebtAccount.DebtType.STUDENT_LOAN,
            "financial_account": str(second_liability.pk),
            "notes": "Renamed to match lender",
            "reason": "Clarifying the account name",
        },
    )
    assert edited_response.status_code == 302
    created.refresh_from_db()
    assert created.name == "Federal student loan"

    terms_response = client.post(
        reverse("debts:terms-create", args=(created.pk,)),
        {
            "effective_from": "2026-09-01",
            "annual_percentage_rate": "4.2500",
            "interest_method": DebtTermsRevision.InterestMethod.MONTHLY,
            "day_count_basis": DebtTermsRevision.DayCountBasis.ACTUAL_365,
            "minimum_payment": "130.00",
            "recurring_extra_payment": "20.00",
            "due_day": "8",
            "custom_priority": "5",
            "projection_notes": "New repayment plan",
            "reason": "Lender approved a new plan",
        },
    )
    assert terms_response.status_code == 302
    assert created.terms_revisions.count() == 2
    assert AuditEvent.objects.filter(action="debt.account_updated").exists()
    assert AuditEvent.objects.filter(action="debt.terms_revised").exists()


@pytest.mark.django_db
def test_statement_correction_and_status_workflows_preserve_history(
    client: Client,
    debt_ui_context: DebtUiContext,
) -> None:
    _mfa_ready(debt_ui_context.user)
    client.force_login(debt_ui_context.user)

    reconciled = client.post(
        reverse("debts:statement-create", args=(debt_ui_context.debt.pk,)),
        _statement_payload(),
    )
    assert reconciled.status_code == 302
    original = DebtStatement.objects.get(debt=debt_ui_context.debt)
    debt_ui_context.debt.refresh_from_db()
    assert debt_ui_context.debt.current_balance == Decimal("17910.20")

    correction_payload = _statement_payload(balance="17895.20")
    correction_payload.update(
        {
            "reason": "Corrected lender transcription",
            "confirm": "on",
        }
    )
    corrected = client.post(
        reverse(
            "debts:statement-correct",
            args=(debt_ui_context.debt.pk, original.pk),
        ),
        correction_payload,
    )
    assert corrected.status_code == 302
    correction = DebtStatement.objects.get(supersedes=original)
    assert correction.statement_balance == Decimal("17895.20")
    assert DebtStatement.objects.filter(debt=debt_ui_context.debt).count() == 2
    assert (
        client.get(
            reverse(
                "debts:statement-correct",
                args=(debt_ui_context.debt.pk, original.pk),
            )
        ).status_code
        == 404
    )

    detail = client.get(reverse("debts:detail", args=(debt_ui_context.debt.pk,)))
    assert detail.status_code == 200
    assert b"Superseded" in detail.content
    assert b"Correction" in detail.content

    archive_url = reverse("debts:status", args=(debt_ui_context.debt.pk, "archive"))
    unconfirmed = client.post(archive_url, {"reason": "Loan moved off current view"})
    assert unconfirmed.status_code == 200
    debt_ui_context.debt.refresh_from_db()
    assert debt_ui_context.debt.status == DebtAccount.Status.ACTIVE
    archived = client.post(
        archive_url,
        {"reason": "Loan moved off current view", "confirm": "on"},
    )
    assert archived.status_code == 302
    debt_ui_context.debt.refresh_from_db()
    assert debt_ui_context.debt.status == DebtAccount.Status.ARCHIVED
    empty_projection = client.get(reverse("debts:payoff-comparison"))
    assert empty_projection.status_code == 200
    assert b"No active balances to project" in empty_projection.content
    assert AuditEvent.objects.filter(action="debt.statement_reconciled").exists()
    assert AuditEvent.objects.filter(action="debt.statement_corrected").exists()
    assert AuditEvent.objects.filter(action="debt.status_changed").exists()


@pytest.mark.django_db
def test_invalid_general_debt_forms_emit_minimized_security_events(
    client: Client,
    debt_ui_context: DebtUiContext,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _mfa_ready(debt_ui_context.user)
    client.force_login(debt_ui_context.user)
    created = client.post(
        reverse("debts:statement-create", args=(debt_ui_context.debt.pk,)),
        _statement_payload(),
    )
    assert created.status_code == 302
    statement = DebtStatement.objects.get(debt=debt_ui_context.debt)
    canary = "PRIVATE_DEBT_REJECTION_CANARY"
    requests = (
        (reverse("debts:create"), "debt-reject-create"),
        (reverse("debts:edit", args=(debt_ui_context.debt.pk,)), "debt-reject-edit"),
        (
            reverse("debts:terms-create", args=(debt_ui_context.debt.pk,)),
            "debt-reject-terms",
        ),
        (
            reverse("debts:statement-create", args=(debt_ui_context.debt.pk,)),
            "debt-reject-statement",
        ),
        (
            reverse(
                "debts:statement-correct",
                args=(debt_ui_context.debt.pk, statement.pk),
            ),
            "debt-reject-correction",
        ),
        (
            reverse("debts:status", args=(debt_ui_context.debt.pk, "archive")),
            "debt-reject-status",
        ),
    )

    with caplog.at_level(logging.WARNING, logger="security"):
        responses = [
            client.post(
                url,
                {"name": canary, "notes": canary, "reason": canary},
                headers={"X-Request-ID": request_id},
            )
            for url, request_id in requests
        ]

    assert [response.status_code for response in responses] == [200] * 6
    expected_events = [
        "debt.create_rejected",
        "debt.edit_rejected",
        "debt.terms_rejected",
        "debt.statement_rejected",
        "debt.statement_correction_rejected",
        "debt.status_rejected",
    ]
    records = [
        record for record in caplog.records if getattr(record, "event", None) in expected_events
    ]
    assert [record.event for record in records] == expected_events  # type: ignore[attr-defined]
    assert [record.error_reference for record in records] == [  # type: ignore[attr-defined]
        request_id for _url, request_id in requests
    ]
    payloads = [json.loads(RedactingJsonFormatter().format(record)) for record in records]
    assert all(canary not in json.dumps(payload) for payload in payloads)
    assert all(
        not {
            "amount",
            "balance",
            "name",
            "notes",
            "reason",
            "debt_id",
            "statement_id",
            "status",
        }.intersection(payload)
        for payload in payloads
    )


@pytest.mark.django_db
def test_service_level_general_debt_rejections_emit_minimized_security_events(
    client: Client,
    debt_ui_context: DebtUiContext,
    caplog: pytest.LogCaptureFixture,
) -> None:
    second_liability = create_financial_account(
        household=debt_ui_context.household,
        actor=debt_ui_context.user,
        name="Service rejection lender",
        account_type=FinancialAccount.AccountType.OTHER,
        classification=FinancialAccount.Classification.LIABILITY,
        request_id="debt-service-rejection-liability",
    )
    _mfa_ready(debt_ui_context.user)
    client.force_login(debt_ui_context.user)
    created = client.post(
        reverse("debts:statement-create", args=(debt_ui_context.debt.pk,)),
        _statement_payload(),
    )
    assert created.status_code == 302
    statement = DebtStatement.objects.get(debt=debt_ui_context.debt)
    canary = "PRIVATE_DEBT_SERVICE_REJECTION_CANARY"
    terms_payload = {
        "effective_from": "2026-09-01",
        "annual_percentage_rate": "7.0000",
        "interest_method": DebtTermsRevision.InterestMethod.MONTHLY,
        "day_count_basis": DebtTermsRevision.DayCountBasis.ACTUAL_365,
        "minimum_payment": "230.00",
        "recurring_extra_payment": "25.00",
        "due_day": "15",
        "custom_priority": "20",
        "projection_notes": "Synthetic terms",
        "reason": "Synthetic terms",
    }
    correction_payload = _statement_payload(balance="17895.20")
    correction_payload.update({"reason": "Synthetic correction", "confirm": "on"})
    workflows = (
        (
            "debts.views.create_debt_account",
            reverse("debts:create"),
            _create_payload(second_liability),
            "debt.create_rejected",
            "debt-service-create",
        ),
        (
            "debts.views.update_debt_account",
            reverse("debts:edit", args=(debt_ui_context.debt.pk,)),
            {
                "name": "Synthetic edit",
                "debt_type": DebtAccount.DebtType.AUTO_LOAN,
                "financial_account": str(debt_ui_context.liability.pk),
                "notes": "Synthetic edit",
                "reason": "Synthetic edit",
            },
            "debt.edit_rejected",
            "debt-service-edit",
        ),
        (
            "debts.views.revise_debt_terms",
            reverse("debts:terms-create", args=(debt_ui_context.debt.pk,)),
            terms_payload,
            "debt.terms_rejected",
            "debt-service-terms",
        ),
        (
            "debts.views.reconcile_debt_statement",
            reverse("debts:statement-create", args=(debt_ui_context.debt.pk,)),
            _statement_payload(balance="17800.00"),
            "debt.statement_rejected",
            "debt-service-statement",
        ),
        (
            "debts.views.reconcile_debt_statement",
            reverse(
                "debts:statement-correct",
                args=(debt_ui_context.debt.pk, statement.pk),
            ),
            correction_payload,
            "debt.statement_correction_rejected",
            "debt-service-correction",
        ),
        (
            "debts.views.change_debt_status",
            reverse("debts:status", args=(debt_ui_context.debt.pk, "archive")),
            {"reason": "Synthetic status", "confirm": "on"},
            "debt.status_rejected",
            "debt-service-status",
        ),
    )

    with caplog.at_level(logging.WARNING, logger="security"):
        for target, url, data, _event, request_id in workflows:
            with patch(target, side_effect=ValidationError(canary)):
                response = client.post(url, data, headers={"X-Request-ID": request_id})
            assert response.status_code == 200

    expected_events = [event for _target, _url, _data, event, _request_id in workflows]
    records = [
        record for record in caplog.records if getattr(record, "event", None) in expected_events
    ]
    assert [record.event for record in records] == expected_events  # type: ignore[attr-defined]
    assert all(canary not in RedactingJsonFormatter().format(record) for record in records)


@pytest.mark.django_db
def test_debt_routes_and_link_choices_do_not_expose_another_household(
    client: Client,
    debt_ui_context: DebtUiContext,
) -> None:
    other_household = Household.objects.create(name="Other Household")
    other_user = User.objects.create_user(email="other@example.com", password=TEST_PASSWORD)
    HouseholdMembership.objects.create(household=other_household, user=other_user)
    other_liability = create_financial_account(
        household=other_household,
        actor=other_user,
        name="Hidden lender",
        account_type=FinancialAccount.AccountType.OTHER,
        classification=FinancialAccount.Classification.LIABILITY,
        request_id="other-liability",
    )
    hidden_debt, _ = create_debt_account(
        household=other_household,
        actor=other_user,
        name="Hidden debt",
        debt_type=DebtAccount.DebtType.OTHER,
        opening_balance=Decimal("500.00"),
        terms=_terms(minimum="50.00"),
        financial_account=other_liability,
        request_id="other-debt",
    )
    _mfa_ready(debt_ui_context.user)
    client.force_login(debt_ui_context.user)

    assert client.get(reverse("debts:detail", args=(hidden_debt.pk,))).status_code == 404
    create_page = client.get(reverse("debts:create"))
    assert create_page.status_code == 200
    assert b"Hidden lender" not in create_page.content
    assert b"Hidden debt" not in client.get(reverse("debts:list")).content


@pytest.mark.django_db
def test_payoff_comparison_renders_all_strategies_for_active_household_debts(
    client: Client,
    debt_ui_context: DebtUiContext,
) -> None:
    create_debt_account(
        household=debt_ui_context.household,
        actor=debt_ui_context.user,
        name="Credit card",
        debt_type=DebtAccount.DebtType.CREDIT_CARD,
        opening_balance=Decimal("1200.00"),
        terms=DebtTermsSpec(
            effective_from=date(2020, 1, 1),
            annual_percentage_rate=Decimal("22.0000"),
            interest_method=DebtTermsRevision.InterestMethod.MONTHLY,
            day_count_basis=DebtTermsRevision.DayCountBasis.ACTUAL_365,
            minimum_payment=Decimal("75.00"),
            custom_priority=1,
        ),
        request_id="debt-ui-card",
    )
    _mfa_ready(debt_ui_context.user)
    client.force_login(debt_ui_context.user)

    initial = client.get(reverse("debts:payoff-comparison"))
    assert initial.status_code == 200
    assert b"Run comparison" in initial.content
    assert b"Minimum payments only" not in initial.content

    response = client.get(
        reverse("debts:payoff-comparison"),
        {"monthly_extra": "200.00", "start_date": "2026-08-23", "maximum_years": "40"},
    )
    assert response.status_code == 200
    for label in (
        b"Minimum payments only",
        b"Snowball",
        b"Avalanche",
        b"Custom priority",
    ):
        assert label in response.content
    assert len(response.context["comparison_rows"]) == 4
    assert b"Recorded lender statements control historical actuals" in response.content
