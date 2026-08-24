from __future__ import annotations

import csv
import io
import time
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from urllib.parse import parse_qs, urlparse
from zoneinfo import ZoneInfo

import pytest
from django.conf import settings
from django.test import Client
from django.urls import reverse

from audit.models import AuditEvent, AuditHead
from audit.services import verify_household_chain
from households.models import Category, Household, HouseholdMembership
from households.services.categories import create_category
from identity.models import User
from identity.services.mfa import (
    begin_enrollment,
    confirm_enrollment,
    confirm_recovery_codes_saved,
    totp_code,
)
from identity.services.sessions import SESSION_AUTH_VERIFIED_AT
from ledger.models import FinancialAccount, JournalEntry
from ledger.services import create_financial_account, record_expense, reverse_entry
from periods.models import PayPeriod
from spending.services import formula_safe_text

TEST_PASSWORD = "csv-export-test-password"  # pragma: allowlist secret


@dataclass(frozen=True, slots=True)
class ExportContext:
    household: Household
    user: User
    period: PayPeriod
    account: FinancialAccount
    category: Category


def _mfa_ready(user: User) -> None:
    enrollment = begin_enrollment(user)
    assert confirm_enrollment(user, totp_code(enrollment.secret)) is not None
    assert confirm_recovery_codes_saved(user) is True
    user.refresh_from_db()


@pytest.fixture
def export_context(db: object) -> ExportContext:
    household = Household.objects.create(name="Export Household")
    user = User.objects.create_user(
        email="exporter@example.com",
        password=TEST_PASSWORD,
        display_name="Export Member",
    )
    HouseholdMembership.objects.create(household=household, user=user)
    period = PayPeriod.objects.create(
        household=household,
        start_date=date(2026, 8, 20),
        next_start_date=date(2026, 8, 27),
        status=PayPeriod.Status.OPEN,
        created_by=user,
    )
    account = create_financial_account(
        household=household,
        actor=user,
        name="-Checking",
        account_type=FinancialAccount.AccountType.CHECKING,
        classification=FinancialAccount.Classification.ASSET,
        request_id="csv-export-account",
    )
    category = create_category(
        household=household,
        actor=user,
        name="@Groceries",
        color="#49D6A6",
        sort_order=10,
        request_id="csv-export-category",
    )
    _mfa_ready(user)
    return ExportContext(household, user, period, account, category)


def _authenticate(client: Client, context: ExportContext) -> None:
    client.force_login(context.user)
    response = client.get(reverse("spending:transaction-list"))
    assert response.status_code == 200


def _csv_rows(response: object) -> list[dict[str, str]]:
    chunks = response.streaming_content  # type: ignore[attr-defined]
    document = b"".join(chunks).decode("utf-8")
    return list(csv.DictReader(io.StringIO(document, newline="")))


@pytest.mark.parametrize(
    "value",
    ("=SUM(1,1)", "+cmd", "-payload", "@lookup", " \t=HYPERLINK('x')", "\r\n+cmd"),
)
def test_formula_safe_text_neutralizes_spreadsheet_prefixes(value: str) -> None:
    assert formula_safe_text(value) == f"'{value}"


def test_formula_safe_text_preserves_ordinary_text() -> None:
    assert formula_safe_text("Neighborhood Market") == "Neighborhood Market"
    assert formula_safe_text("  ordinary note") == "  ordinary note"
    assert formula_safe_text("") == ""


@pytest.mark.django_db
def test_transaction_export_requires_login(client: Client) -> None:
    response = client.get(reverse("spending:transaction-export"))

    assert response.status_code == 302
    assert response.headers["Location"].startswith(reverse("identity:login"))


@pytest.mark.django_db
def test_transaction_export_requires_recent_reauthentication(
    client: Client,
    export_context: ExportContext,
) -> None:
    _authenticate(client, export_context)
    session = client.session
    session[SESSION_AUTH_VERIFIED_AT] = int(time.time()) - settings.RECENT_AUTH_TIMEOUT_SECONDS - 1
    session.save()
    export_path = f"{reverse('spending:transaction-export')}?scope=all"

    response = client.get(export_path)

    assert response.status_code == 302
    location = urlparse(response.headers["Location"])
    assert location.path == reverse("identity:reauthenticate")
    assert parse_qs(location.query)["next"] == [export_path]
    assert not AuditEvent.objects.filter(action="spending.transactions_exported").exists()


@pytest.mark.django_db
def test_pay_period_export_is_streamed_formula_safe_numeric_and_audited(
    client: Client,
    export_context: ExportContext,
) -> None:
    original = record_expense(
        household=export_context.household,
        actor=export_context.user,
        account=export_context.account,
        category=export_context.category,
        amount=Decimal("15.00"),
        effective_at=datetime(2026, 8, 22, 12, tzinfo=ZoneInfo("America/New_York")),
        description='=HYPERLINK("https://invalid.example")',
        note="+SUM(1,1)",
        receipt_reference="@receipt-payload",
        request_id="csv-export-current-expense",
    )
    reversal = reverse_entry(
        entry=original,
        actor=export_context.user,
        effective_at=datetime(2026, 8, 24, 9, tzinfo=ZoneInfo("America/New_York")),
        reason="Refund received",
        request_id="csv-export-current-reversal",
    )
    record_expense(
        household=export_context.household,
        actor=export_context.user,
        account=export_context.account,
        category=export_context.category,
        amount=Decimal("8.00"),
        effective_at=datetime(2026, 8, 10, 12, tzinfo=ZoneInfo("America/New_York")),
        description="Older transaction",
        request_id="csv-export-older-expense",
    )
    _authenticate(client, export_context)

    response = client.get(
        reverse("spending:transaction-export"),
        {"period": str(export_context.period.pk)},
    )

    assert response.status_code == 200
    assert response.streaming is True
    assert response.headers["Content-Type"] == "text/csv; charset=utf-8"
    assert response.headers["Content-Disposition"].startswith(
        'attachment; filename="budget-transactions-'
    )
    assert response.headers["Content-Disposition"].endswith('.csv"')
    assert response.headers["Cache-Control"] == "no-store, private"
    rows = _csv_rows(response)
    assert len(rows) == 2
    by_id = {row["transaction_id"]: row for row in rows}
    original_row = by_id[str(original.pk)]
    reversal_row = by_id[str(reversal.pk)]
    assert original_row["description"].startswith("'=HYPERLINK")
    assert original_row["account"] == "'-Checking"
    assert original_row["category"] == "'@Groceries"
    assert original_row["note"] == "'+SUM(1,1)"
    assert original_row["receipt_reference"] == "'@receipt-payload"
    assert original_row["amount"] == "15.00"
    assert reversal_row["amount"] == "-15.00"
    assert not reversal_row["amount"].startswith("'")
    assert all(row["description"] != "Older transaction" for row in rows)

    event = AuditEvent.objects.get(action="spending.transactions_exported")
    assert event.household == export_context.household
    assert event.actor == export_context.user
    assert event.entity_type == "transaction_export"
    assert event.after_payload == {
        "filters": {"account_id": "", "entry_type": "", "query_applied": False},
        "period_id": str(export_context.period.pk),
        "row_count": 2,
        "scope": "period",
    }
    assert verify_household_chain(export_context.household).valid is True


@pytest.mark.django_db
def test_transaction_export_applies_filters_and_never_crosses_households(
    client: Client,
    export_context: ExportContext,
) -> None:
    included = record_expense(
        household=export_context.household,
        actor=export_context.user,
        account=export_context.account,
        category=export_context.category,
        amount=Decimal("12.00"),
        effective_at=datetime(2026, 8, 22, 12, tzinfo=ZoneInfo("America/New_York")),
        description="Needle purchase",
        request_id="csv-export-filter-included",
    )
    record_expense(
        household=export_context.household,
        actor=export_context.user,
        account=export_context.account,
        category=export_context.category,
        amount=Decimal("7.00"),
        effective_at=datetime(2026, 8, 23, 12, tzinfo=ZoneInfo("America/New_York")),
        description="Different purchase",
        request_id="csv-export-filter-excluded",
    )
    other_household = Household.objects.create(name="Other Export Household")
    outsider = User.objects.create_user(email="other-exporter@example.com", password=TEST_PASSWORD)
    HouseholdMembership.objects.create(household=other_household, user=outsider)
    other_account = create_financial_account(
        household=other_household,
        actor=outsider,
        name="Other checking",
        account_type=FinancialAccount.AccountType.CHECKING,
        classification=FinancialAccount.Classification.ASSET,
        request_id="csv-export-other-account",
    )
    other_category = create_category(
        household=other_household,
        actor=outsider,
        name="Other category",
        color="#64748B",
        sort_order=0,
        request_id="csv-export-other-category",
    )
    record_expense(
        household=other_household,
        actor=outsider,
        account=other_account,
        category=other_category,
        amount=Decimal("999.00"),
        effective_at=datetime(2026, 8, 22, 12, tzinfo=ZoneInfo("America/New_York")),
        description="Needle private other-household transaction",
        request_id="csv-export-other-expense",
    )
    _authenticate(client, export_context)

    response = client.get(
        reverse("spending:transaction-export"),
        {
            "scope": "all",
            "q": "Needle",
            "entry_type": JournalEntry.EntryType.EXPENSE,
            "account": str(export_context.account.pk),
        },
    )

    rows = _csv_rows(response)
    assert [row["transaction_id"] for row in rows] == [str(included.pk)]
    event = AuditEvent.objects.get(action="spending.transactions_exported")
    assert event.after_payload["scope"] == "all"
    assert event.after_payload["row_count"] == 1
    assert event.after_payload["filters"] == {
        "account_id": str(export_context.account.pk),
        "entry_type": JournalEntry.EntryType.EXPENSE,
        "query_applied": True,
    }


@pytest.mark.django_db
def test_transaction_export_fails_closed_when_audit_integrity_is_invalid(
    client: Client,
    export_context: ExportContext,
) -> None:
    _authenticate(client, export_context)
    AuditHead.objects.filter(household=export_context.household).update(chain_head="f" * 64)

    response = client.get(reverse("spending:transaction-export"))

    assert response.status_code == 409
    assert b"audit integrity verification failed" in response.content
    assert response.headers["Cache-Control"] == "no-store, private"
    assert not AuditEvent.objects.filter(action="spending.transactions_exported").exists()
