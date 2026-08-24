from __future__ import annotations

from dataclasses import replace
from datetime import date
from decimal import Decimal
from pathlib import Path

import pytest
from django.core.exceptions import PermissionDenied, ValidationError

from audit.models import AuditEvent
from audit.services import verify_household_chain
from debts.models import DebtAccount, DebtStatement, DebtTermsRevision
from debts.services import (
    DebtStatementSpec,
    DebtTermsSpec,
    change_debt_status,
    create_debt_account,
    current_debt_terms,
    reconcile_debt_statement,
    revise_debt_terms,
    update_debt_account,
)
from households.models import Household, HouseholdMembership
from identity.models import User
from ledger.models import FinancialAccount
from ledger.services import archive_financial_account, create_financial_account

TEST_PASSWORD = "debt-account-test-password"  # pragma: allowlist secret


@pytest.fixture
def debt_context(db: object) -> tuple[Household, User, User, FinancialAccount]:
    household = Household.objects.create(name="Debt Household")
    user = User.objects.create_user(email="debt-member@example.com", password=TEST_PASSWORD)
    outsider = User.objects.create_user(email="debt-outsider@example.com", password=TEST_PASSWORD)
    HouseholdMembership.objects.create(household=household, user=user)
    liability = create_financial_account(
        household=household,
        actor=user,
        name="Auto loan account",
        account_type=FinancialAccount.AccountType.OTHER,
        classification=FinancialAccount.Classification.LIABILITY,
        request_id="debt-test-liability",
    )
    return household, user, outsider, liability


def _terms(
    *,
    effective_from: date = date(2026, 1, 1),
    apr: str = "6.5000",
    minimum: str = "325.00",
    extra: str = "0.00",
    due_day: int = 15,
    priority: int = 10,
) -> DebtTermsSpec:
    return DebtTermsSpec(
        effective_from=effective_from,
        annual_percentage_rate=Decimal(apr),
        interest_method=DebtTermsRevision.InterestMethod.MONTHLY,
        day_count_basis=DebtTermsRevision.DayCountBasis.ACTUAL_365,
        minimum_payment=Decimal(minimum),
        recurring_extra_payment=Decimal(extra),
        due_day=due_day,
        custom_priority=priority,
    )


def _create_debt(
    household: Household,
    user: User,
    liability: FinancialAccount,
) -> tuple[DebtAccount, DebtTermsRevision]:
    return create_debt_account(
        household=household,
        actor=user,
        name="Family car",
        debt_type=DebtAccount.DebtType.AUTO_LOAN,
        opening_balance=Decimal("18500.00"),
        terms=_terms(),
        financial_account=liability,
        notes="Opening lender balance",
        request_id="debt-test-create",
    )


@pytest.mark.django_db
def test_create_debt_is_household_scoped_service_only_and_audited(
    debt_context: tuple[Household, User, User, FinancialAccount],
) -> None:
    household, user, _, liability = debt_context
    debt, terms = _create_debt(household, user, liability)

    assert debt.household == household
    assert debt.financial_account == liability
    assert debt.current_balance == Decimal("18500.00")
    assert terms.revision_number == 1
    assert current_debt_terms(debt, on_date=date(2026, 1, 1)) == terms
    event = AuditEvent.objects.get(action="debt.account_created", entity_id=str(debt.pk))
    assert event.after_payload["opening_balance"] == "18500.00"
    assert event.after_payload["terms"]["annual_percentage_rate"] == "6.5000"
    assert verify_household_chain(household).valid is True

    with pytest.raises(ValidationError, match="must use a debt service"):
        DebtAccount.objects.create(
            household=household,
            name="Bypass",
            debt_type=DebtAccount.DebtType.OTHER,
            current_balance=Decimal("1.00"),
            created_by=user,
            updated_by=user,
        )
    debt.name = "Direct mutation"
    with pytest.raises(ValidationError, match="must use a debt service"):
        debt.save()
    with pytest.raises(ValidationError, match="must use a debt service"):
        DebtAccount.objects.filter(pk=debt.pk).update(name="Query bypass")
    with pytest.raises(ValidationError, match="cannot be deleted"):
        debt.delete()
    with pytest.raises(ValidationError, match="cannot be deleted"):
        DebtAccount.objects.all().delete()
    with pytest.raises(ValidationError, match="must use a debt service"):
        DebtAccount.objects.bulk_create([])
    with pytest.raises(ValidationError, match="must use a debt service"):
        DebtAccount.objects.bulk_update([], ("name",))
    with pytest.raises(ValidationError, match="must use a debt service"):
        DebtTermsRevision.objects.create()
    with pytest.raises(ValidationError, match="cannot be deleted"):
        DebtTermsRevision.objects.all().delete()


@pytest.mark.django_db
def test_debt_terms_are_effective_dated_immutable_and_reason_audited(
    debt_context: tuple[Household, User, User, FinancialAccount],
) -> None:
    household, user, _, liability = debt_context
    debt, original = _create_debt(household, user, liability)
    revised_spec = _terms(
        effective_from=date(2026, 6, 1),
        apr="5.7500",
        minimum="340.00",
        extra="25.00",
        priority=4,
    )

    revised = revise_debt_terms(
        debt=debt,
        actor=user,
        terms=revised_spec,
        request_id="debt-test-revise",
        reason="Lender rate adjustment",
    )

    assert revised.revision_number == 2
    assert current_debt_terms(debt, on_date=date(2026, 5, 31)) == original
    assert current_debt_terms(debt, on_date=date(2026, 6, 1)) == revised
    event = AuditEvent.objects.get(action="debt.terms_revised", entity_id=str(revised.pk))
    assert event.reason == "Lender rate adjustment"
    assert event.before_payload["annual_percentage_rate"] == "6.5000"
    assert event.after_payload["annual_percentage_rate"] == "5.7500"

    revised.minimum_payment = Decimal("1.00")
    with pytest.raises(ValidationError, match="cannot be updated"):
        revised.save()
    with pytest.raises(ValidationError, match="cannot be deleted"):
        revised.delete()
    with pytest.raises(ValidationError, match="must begin after"):
        revise_debt_terms(
            debt=debt,
            actor=user,
            terms=_terms(effective_from=date(2026, 5, 1)),
            request_id="debt-test-backdated-revision",
            reason="Invalid backdate",
        )
    with pytest.raises(ValidationError, match="requires a reason"):
        revise_debt_terms(
            debt=debt,
            actor=user,
            terms=_terms(effective_from=date(2026, 7, 1)),
            request_id="debt-test-revision-no-reason",
            reason="",
        )


@pytest.mark.django_db
def test_statement_reconciliation_preserves_components_and_uses_corrections(
    debt_context: tuple[Household, User, User, FinancialAccount],
) -> None:
    household, user, _, liability = debt_context
    debt, _ = _create_debt(household, user, liability)
    statement_spec = DebtStatementSpec(
        statement_date=date(2026, 2, 28),
        period_start=date(2026, 2, 1),
        period_end=date(2026, 2, 28),
        due_date=date(2026, 3, 15),
        statement_balance=Decimal("18190.00"),
        annual_percentage_rate=Decimal("6.5000"),
        minimum_payment=Decimal("325.00"),
        principal_paid=Decimal("225.00"),
        interest_charged=Decimal("100.00"),
        fees_charged=Decimal("5.00"),
        escrow_paid=Decimal("250.00"),
        notes="February lender statement",
    )

    statement = reconcile_debt_statement(
        debt=debt,
        actor=user,
        statement=statement_spec,
        request_id="debt-test-reconcile",
    )
    debt.refresh_from_db()

    assert debt.current_balance == Decimal("18190.00")
    assert debt.last_reconciled_on == date(2026, 2, 28)
    assert statement.escrow_paid == Decimal("250.00")
    assert statement.principal_paid == Decimal("225.00")
    event = AuditEvent.objects.get(action="debt.statement_reconciled", entity_id=str(statement.pk))
    assert event.after_payload["escrow_paid"] == "250.00"

    correction = reconcile_debt_statement(
        debt=debt,
        actor=user,
        statement=replace(statement_spec, statement_balance=Decimal("18180.00")),
        request_id="debt-test-correction",
        supersedes=statement,
        reason="Corrected lender transcription",
    )
    debt.refresh_from_db()
    assert debt.current_balance == Decimal("18180.00")
    assert correction.supersedes == statement
    assert statement.superseded_by == correction
    assert AuditEvent.objects.get(action="debt.statement_corrected").reason == (
        "Corrected lender transcription"
    )

    with pytest.raises(ValidationError, match="already been corrected"):
        reconcile_debt_statement(
            debt=debt,
            actor=user,
            statement=statement_spec,
            request_id="debt-test-second-correction",
            supersedes=statement,
            reason="Invalid second correction",
        )
    correction.notes = "Direct edit"
    with pytest.raises(ValidationError, match="cannot be updated"):
        correction.save()
    with pytest.raises(ValidationError, match="cannot be deleted"):
        correction.delete()
    with pytest.raises(ValidationError, match="must use a debt service"):
        DebtStatement.objects.filter(pk=correction.pk).update(statement_balance=Decimal("1.00"))


@pytest.mark.django_db
def test_zero_balance_reconciliation_marks_paid_off_and_correction_can_reopen(
    debt_context: tuple[Household, User, User, FinancialAccount],
) -> None:
    household, user, _, liability = debt_context
    debt, _ = _create_debt(household, user, liability)
    paid = reconcile_debt_statement(
        debt=debt,
        actor=user,
        statement=DebtStatementSpec(
            statement_date=date(2026, 3, 31),
            statement_balance=Decimal("0.00"),
            annual_percentage_rate=Decimal("0.0000"),
            minimum_payment=Decimal("0.00"),
        ),
        request_id="debt-test-paid-off",
    )
    debt.refresh_from_db()
    assert debt.status == DebtAccount.Status.PAID_OFF
    assert debt.status_changed_at is not None

    reconcile_debt_statement(
        debt=debt,
        actor=user,
        statement=DebtStatementSpec(
            statement_date=date(2026, 3, 31),
            statement_balance=Decimal("10.00"),
            annual_percentage_rate=Decimal("0.0000"),
            minimum_payment=Decimal("10.00"),
        ),
        request_id="debt-test-reopen-correction",
        supersedes=paid,
        reason="Final fee appeared on corrected statement",
    )
    debt.refresh_from_db()
    assert debt.status == DebtAccount.Status.ACTIVE
    assert debt.status_changed_at is None


@pytest.mark.django_db
def test_historical_statement_correction_does_not_roll_current_balance_backward(
    debt_context: tuple[Household, User, User, FinancialAccount],
) -> None:
    household, user, _, liability = debt_context
    debt, _ = _create_debt(household, user, liability)
    january = reconcile_debt_statement(
        debt=debt,
        actor=user,
        statement=DebtStatementSpec(
            statement_date=date(2026, 1, 31),
            statement_balance=Decimal("18200.00"),
            annual_percentage_rate=Decimal("6.5000"),
            minimum_payment=Decimal("325.00"),
        ),
        request_id="debt-january-statement",
    )
    reconcile_debt_statement(
        debt=debt,
        actor=user,
        statement=DebtStatementSpec(
            statement_date=date(2026, 2, 28),
            statement_balance=Decimal("17900.00"),
            annual_percentage_rate=Decimal("6.5000"),
            minimum_payment=Decimal("325.00"),
        ),
        request_id="debt-february-statement",
    )

    correction = reconcile_debt_statement(
        debt=debt,
        actor=user,
        statement=DebtStatementSpec(
            statement_date=date(2026, 1, 31),
            statement_balance=Decimal("18190.00"),
            annual_percentage_rate=Decimal("6.5000"),
            minimum_payment=Decimal("325.00"),
        ),
        supersedes=january,
        reason="Correct the historical transcription",
        request_id="debt-january-correction",
    )

    debt.refresh_from_db()
    assert correction.supersedes == january
    assert debt.current_balance == Decimal("17900.00")
    assert debt.last_reconciled_on == date(2026, 2, 28)


@pytest.mark.django_db
def test_debt_metadata_status_and_cross_household_access_fail_closed(
    debt_context: tuple[Household, User, User, FinancialAccount],
) -> None:
    household, user, outsider, liability = debt_context
    debt, _ = _create_debt(household, user, liability)

    updated = update_debt_account(
        debt=debt,
        actor=user,
        name="Family vehicle",
        debt_type=DebtAccount.DebtType.AUTO_LOAN,
        financial_account=liability,
        notes="Renamed for clarity",
        request_id="debt-test-update",
        reason="Use current vehicle name",
    )
    assert updated.name == "Family vehicle"
    assert AuditEvent.objects.get(action="debt.account_updated").reason == (
        "Use current vehicle name"
    )
    archived = change_debt_status(
        debt=updated,
        actor=user,
        status=DebtAccount.Status.ARCHIVED,
        request_id="debt-test-archive",
        reason="Refinanced elsewhere",
    )
    assert archived.status == DebtAccount.Status.ARCHIVED

    with pytest.raises(PermissionDenied):
        update_debt_account(
            debt=debt,
            actor=outsider,
            name="Unauthorized",
            debt_type=DebtAccount.DebtType.AUTO_LOAN,
            financial_account=liability,
            notes="",
            request_id="debt-test-outsider",
            reason="Unauthorized",
        )


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("debt_type", "opening_balance", "terms", "message"),
    (
        ("not-a-type", Decimal("1.00"), _terms(), "type is invalid"),
        (
            DebtAccount.DebtType.OTHER,
            Decimal("1.00"),
            _terms(effective_from=date(2099, 1, 1)),
            "cannot begin in the future",
        ),
        (DebtAccount.DebtType.OTHER, Decimal("-1.00"), _terms(), "nonnegative"),
        (DebtAccount.DebtType.OTHER, Decimal("1.001"), _terms(), "two decimals"),
        (DebtAccount.DebtType.OTHER, Decimal("NaN"), _terms(), "finite Decimal"),
        (
            DebtAccount.DebtType.OTHER,
            Decimal("1.00"),
            replace(_terms(), annual_percentage_rate=Decimal("1000.0000")),
            "between 0 and 999.9999",
        ),
        (
            DebtAccount.DebtType.OTHER,
            Decimal("1.00"),
            replace(_terms(), interest_method="invalid"),
            "interest method is invalid",
        ),
        (
            DebtAccount.DebtType.OTHER,
            Decimal("1.00"),
            replace(_terms(), day_count_basis="invalid"),
            "day-count basis is invalid",
        ),
        (
            DebtAccount.DebtType.OTHER,
            Decimal("1.00"),
            replace(_terms(), due_day=0),
            "due day must be between",
        ),
        (
            DebtAccount.DebtType.OTHER,
            Decimal("1.00"),
            replace(_terms(), custom_priority=0),
            "priority must be positive",
        ),
        (
            DebtAccount.DebtType.OTHER,
            Decimal("1.00"),
            replace(_terms(), projection_notes="x" * 501),
            "notes cannot exceed",
        ),
    ),
)
def test_debt_creation_rejects_invalid_money_terms_and_types(
    debt_context: tuple[Household, User, User, FinancialAccount],
    debt_type: str,
    opening_balance: Decimal,
    terms: DebtTermsSpec,
    message: str,
) -> None:
    household, user, _, liability = debt_context
    with pytest.raises(ValidationError, match=message):
        create_debt_account(
            household=household,
            actor=user,
            name="Rejected debt",
            debt_type=debt_type,
            opening_balance=opening_balance,
            terms=terms,
            financial_account=liability,
            request_id="debt-invalid-create",
        )
    assert not DebtAccount.objects.filter(name="Rejected debt").exists()


@pytest.mark.django_db
def test_debt_account_link_validation_rejects_unsafe_accounts(
    debt_context: tuple[Household, User, User, FinancialAccount],
) -> None:
    household, user, _, _ = debt_context
    asset = create_financial_account(
        household=household,
        actor=user,
        name="Checking",
        account_type=FinancialAccount.AccountType.CHECKING,
        classification=FinancialAccount.Classification.ASSET,
        request_id="debt-invalid-asset",
    )
    archived = create_financial_account(
        household=household,
        actor=user,
        name="Old lender",
        account_type=FinancialAccount.AccountType.OTHER,
        classification=FinancialAccount.Classification.LIABILITY,
        request_id="debt-invalid-archived",
    )
    archive_financial_account(
        account=archived,
        actor=user,
        request_id="debt-archive-linked-account",
        reason="Closed lender account",
    )
    other_household = Household.objects.create(name="Other Debt Household")
    other_user = User.objects.create_user(email="other-debt@example.com", password=TEST_PASSWORD)
    HouseholdMembership.objects.create(household=other_household, user=other_user)
    foreign = create_financial_account(
        household=other_household,
        actor=other_user,
        name="Foreign lender",
        account_type=FinancialAccount.AccountType.OTHER,
        classification=FinancialAccount.Classification.LIABILITY,
        request_id="debt-invalid-foreign",
    )

    for account, message in (
        (asset, "liability account"),
        (archived, "Archived financial accounts"),
        (foreign, "another household"),
    ):
        with pytest.raises(ValidationError, match=message):
            create_debt_account(
                household=household,
                actor=user,
                name=f"Rejected {account.name}",
                debt_type=DebtAccount.DebtType.OTHER,
                opening_balance=Decimal("100.00"),
                terms=_terms(),
                financial_account=account,
                request_id="debt-invalid-link",
            )

    with pytest.raises(ValidationError, match="credit-card account"):
        create_debt_account(
            household=household,
            actor=user,
            name="Mismatched card",
            debt_type=DebtAccount.DebtType.CREDIT_CARD,
            opening_balance=Decimal("100.00"),
            terms=_terms(),
            financial_account=create_financial_account(
                household=household,
                actor=user,
                name="Generic liability",
                account_type=FinancialAccount.AccountType.OTHER,
                classification=FinancialAccount.Classification.LIABILITY,
                request_id="debt-generic-liability",
            ),
            request_id="debt-invalid-credit-card",
        )


@pytest.mark.django_db
def test_debt_revisions_statements_updates_and_statuses_fail_closed(
    debt_context: tuple[Household, User, User, FinancialAccount],
) -> None:
    household, user, _, liability = debt_context
    debt, _ = _create_debt(household, user, liability)
    other_debt, _ = create_debt_account(
        household=household,
        actor=user,
        name="Other loan",
        debt_type=DebtAccount.DebtType.OTHER,
        opening_balance=Decimal("500.00"),
        terms=_terms(minimum="50.00"),
        request_id="debt-other-loan",
    )
    original_spec = DebtStatementSpec(
        statement_date=date(2026, 4, 30),
        statement_balance=Decimal("18000.00"),
        annual_percentage_rate=Decimal("6.5000"),
        minimum_payment=Decimal("325.00"),
    )
    original = reconcile_debt_statement(
        debt=debt,
        actor=user,
        statement=original_spec,
        request_id="debt-rejection-original",
    )
    foreign_statement = reconcile_debt_statement(
        debt=other_debt,
        actor=user,
        statement=replace(original_spec, statement_balance=Decimal("450.00")),
        request_id="debt-rejection-foreign-statement",
    )

    for invalid_type, reason, message in (
        ("invalid", "Valid reason", "type is invalid"),
        (DebtAccount.DebtType.AUTO_LOAN, "", "requires a reason"),
    ):
        with pytest.raises(ValidationError, match=message):
            update_debt_account(
                debt=debt,
                actor=user,
                name="Unchanged",
                debt_type=invalid_type,
                financial_account=liability,
                notes="",
                request_id="debt-invalid-update",
                reason=reason,
            )

    with pytest.raises(ValidationError, match="already reconciled"):
        reconcile_debt_statement(
            debt=debt,
            actor=user,
            statement=original_spec,
            request_id="debt-duplicate-statement",
        )
    with pytest.raises(ValidationError, match="predate"):
        reconcile_debt_statement(
            debt=debt,
            actor=user,
            statement=replace(original_spec, statement_date=date(2026, 3, 31)),
            request_id="debt-old-statement",
        )
    with pytest.raises(ValidationError, match="requires a reason"):
        reconcile_debt_statement(
            debt=debt,
            actor=user,
            statement=original_spec,
            supersedes=original,
            request_id="debt-correction-no-reason",
        )
    with pytest.raises(ValidationError, match="original statement date"):
        reconcile_debt_statement(
            debt=debt,
            actor=user,
            statement=replace(original_spec, statement_date=date(2026, 5, 1)),
            supersedes=original,
            reason="Wrong date",
            request_id="debt-correction-wrong-date",
        )
    with pytest.raises(ValidationError, match="another debt"):
        reconcile_debt_statement(
            debt=debt,
            actor=user,
            statement=original_spec,
            supersedes=foreign_statement,
            reason="Wrong debt",
            request_id="debt-correction-wrong-debt",
        )
    for status, reason, message in (
        ("invalid", "Valid reason", "status is invalid"),
        (DebtAccount.Status.ARCHIVED, "", "requires a reason"),
    ):
        with pytest.raises(ValidationError, match=message):
            change_debt_status(
                debt=debt,
                actor=user,
                status=status,
                request_id="debt-invalid-status",
                reason=reason,
            )

    archived = change_debt_status(
        debt=debt,
        actor=user,
        status=DebtAccount.Status.ARCHIVED,
        request_id="debt-rejection-archive",
        reason="Archived for rejection tests",
    )
    with pytest.raises(ValidationError, match="Archived debts"):
        reconcile_debt_statement(
            debt=archived,
            actor=user,
            statement=replace(original_spec, statement_date=date(2026, 5, 31)),
            request_id="debt-archived-statement",
        )
    with pytest.raises(ValidationError, match="Only active debts"):
        revise_debt_terms(
            debt=archived,
            actor=user,
            terms=_terms(effective_from=date(2026, 6, 1)),
            request_id="debt-archived-revision",
            reason="Should fail",
        )
    with pytest.raises(ValidationError, match="zero-balance"):
        change_debt_status(
            debt=debt,
            actor=user,
            status=DebtAccount.Status.PAID_OFF,
            request_id="debt-test-invalid-payoff",
            reason="Not actually paid",
        )


def test_postgresql_migration_protects_terms_and_statements() -> None:
    migration_path = (
        Path(__file__).parents[1] / "debts" / "migrations" / "0002_postgresql_protect_history.py"
    )
    source = migration_path.read_text(encoding="utf-8")
    assert "debts_debttermsrevision" in source
    assert "debts_debtstatement" in source
    assert "BEFORE UPDATE OR DELETE" in source
    assert "BEFORE TRUNCATE" in source
