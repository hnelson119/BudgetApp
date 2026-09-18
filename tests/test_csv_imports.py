from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from decimal import Decimal
from io import StringIO
from unittest.mock import patch
from zoneinfo import ZoneInfo

import pytest
from django.conf import settings
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import Client, override_settings
from django.urls import reverse
from django.utils import timezone

from audit.models import AuditEvent
from core.logging import RedactingJsonFormatter
from households.models import Category, Household, HouseholdMembership
from households.services.categories import create_category
from identity.models import User
from identity.services.mfa import (
    begin_enrollment,
    confirm_enrollment,
    confirm_recovery_codes_saved,
    totp_code,
)
from imports.forms import CSVUploadForm
from imports.models import ImportBatch, ImportRow
from imports.services import (
    abandon_import_batch,
    commit_import_batch,
    expire_stale_import_batches,
    parse_csv_upload,
    preview_import_batch,
    stage_csv_import,
)
from ledger.models import FinancialAccount, JournalEntry
from ledger.services import (
    archive_financial_account,
    calculated_account_balance,
    create_financial_account,
)
from periods.models import PayPeriod
from reserves.models import CardPaymentReserveEntry
from spending.services import credit_card_payment_reserve, record_spending_expense

TEST_PASSWORD = "csv-import-test-password"  # pragma: allowlist secret


@dataclass(frozen=True, slots=True)
class ImportContext:
    household: Household
    user: User
    spouse: User
    outsider: User
    checking: FinancialAccount
    card: FinancialAccount
    groceries: Category
    dining: Category


def _mfa_ready(user: User) -> None:
    enrollment = begin_enrollment(user)
    assert confirm_enrollment(user, totp_code(enrollment.secret)) is not None
    assert confirm_recovery_codes_saved(user) is True
    user.refresh_from_db()


@pytest.fixture
def import_context(db: object) -> ImportContext:
    household = Household.objects.create(name="Import Household")
    user = User.objects.create_user(email="importer@example.com", password=TEST_PASSWORD)
    spouse = User.objects.create_user(email="spouse@example.com", password=TEST_PASSWORD)
    outsider = User.objects.create_user(email="outsider@example.com", password=TEST_PASSWORD)
    HouseholdMembership.objects.create(household=household, user=user)
    HouseholdMembership.objects.create(household=household, user=spouse)
    checking = create_financial_account(
        household=household,
        actor=user,
        name="Import Checking",
        account_type=FinancialAccount.AccountType.CHECKING,
        classification=FinancialAccount.Classification.ASSET,
        request_id="csv-account-checking",
    )
    card = create_financial_account(
        household=household,
        actor=user,
        name="Import Card",
        account_type=FinancialAccount.AccountType.CREDIT_CARD,
        classification=FinancialAccount.Classification.LIABILITY,
        request_id="csv-account-card",
    )
    groceries = create_category(
        household=household,
        actor=user,
        name="Groceries",
        color="#49D6A6",
        sort_order=10,
        request_id="csv-category-groceries",
    )
    dining = create_category(
        household=household,
        actor=user,
        name="Dining",
        color="#F5A623",
        sort_order=20,
        request_id="csv-category-dining",
    )
    PayPeriod.objects.create(
        household=household,
        start_date=date(2026, 8, 20),
        next_start_date=date(2026, 8, 27),
        status=PayPeriod.Status.OPEN,
        created_by=user,
    )
    return ImportContext(household, user, spouse, outsider, checking, card, groceries, dining)


def _upload(content: bytes, *, name: str = "transactions.csv") -> SimpleUploadedFile:
    return SimpleUploadedFile(name, content, content_type="text/csv")


def test_csv_upload_contract_matches_the_documented_release_limits() -> None:
    field = CSVUploadForm.base_fields["csv_file"]

    assert settings.CSV_IMPORT_MAX_BYTES == 5 * 1024 * 1024
    assert settings.DATA_UPLOAD_MAX_MEMORY_SIZE == settings.CSV_IMPORT_MAX_BYTES
    assert settings.FILE_UPLOAD_MAX_MEMORY_SIZE == settings.CSV_IMPORT_MAX_BYTES
    assert settings.CSV_IMPORT_MAX_ROWS == 10_000
    assert settings.CSV_IMPORT_MAX_COLUMNS == 50
    assert settings.CSV_IMPORT_MAX_CELL_LENGTH == 1_000
    assert field.widget.attrs["accept"] == ".csv,text/csv"
    assert field.help_text == (
        "UTF-8 .csv only; maximum 5 MiB and 10,000 transaction rows. Archives are not accepted."
    )


def _stage(
    context: ImportContext,
    content: bytes,
    *,
    account: FinancialAccount | None = None,
    token: uuid.UUID | None = None,
) -> ImportBatch:
    return stage_csv_import(
        household=context.household,
        actor=context.user,
        target_account=account or context.checking,
        upload=_upload(content),
        submission_token=token or uuid.uuid4(),
        request_id="csv-stage-request",
    )


def _preview(
    context: ImportContext,
    batch: ImportBatch,
    *,
    expense_sign: str = "negative",
    default_category: Category | None = None,
) -> ImportBatch:
    return preview_import_batch(
        batch=batch,
        actor=context.user,
        date_column="Date",
        description_column="Description",
        amount_column="Amount",
        category_column="Category",
        date_format="auto",
        expense_sign=expense_sign,
        default_category=default_category,
        request_id="csv-preview-request",
    )


@pytest.mark.django_db
@override_settings(CSV_IMPORT_STAGING_RETENTION_HOURS=24)
def test_stale_csv_cleanup_scrubs_uploaded_and_previewed_batches_with_audit(
    import_context: ImportContext,
) -> None:
    old_uploaded = _stage(
        import_context,
        b"Date,Description,Amount,Category\n08/21/2026,Old upload,-1.00,Dining\n",
    )
    old_previewed = _stage(
        import_context,
        b"Date,Description,Amount,Category\n08/22/2026,Old preview,-2.00,Dining\n",
    )
    _preview(import_context, old_previewed)
    recent = _stage(
        import_context,
        b"Date,Description,Amount,Category\n08/23/2026,Recent,-3.00,Dining\n",
    )
    now = timezone.now()
    ImportBatch.objects.filter(pk__in=(old_uploaded.pk, old_previewed.pk)).update(
        uploaded_at=now - timedelta(hours=25)
    )

    assert expire_stale_import_batches(now=now) == 2
    for batch in (old_uploaded, old_previewed):
        batch.refresh_from_db()
        assert batch.status == ImportBatch.Status.ABANDONED
        assert batch.completed_at == now
        assert batch.raw_deleted_at == now
        assert not ImportRow.objects.filter(batch=batch).exclude(raw_data={}).exists()
        event = AuditEvent.objects.get(action="import.batch_expired", entity_id=str(batch.pk))
        assert event.actor is None
        assert event.after_payload == {
            "raw_data_deleted": True,
            "retention_hours": 24,
        }
        assert event.reason == "Staged import exceeded retention period"

    recent.refresh_from_db()
    assert recent.status == ImportBatch.Status.UPLOADED
    assert ImportRow.objects.filter(batch=recent).exclude(raw_data={}).exists()
    assert expire_stale_import_batches(now=now) == 0
    assert AuditEvent.objects.filter(action="import.batch_expired").count() == 2


@pytest.mark.django_db
def test_stale_csv_cleanup_validates_configuration_and_command_is_bounded(
    import_context: ImportContext,
) -> None:
    with pytest.raises(ValidationError, match="time zone"):
        expire_stale_import_batches(now=datetime(2026, 8, 31, 12))
    with override_settings(CSV_IMPORT_STAGING_RETENTION_HOURS=0):
        with pytest.raises(ValidationError, match="between 1 and 720"):
            expire_stale_import_batches()

    batch = _stage(
        import_context,
        b"Date,Description,Amount,Category\n08/24/2026,Command expiry,-4.00,Dining\n",
    )
    ImportBatch.objects.filter(pk=batch.pk).update(uploaded_at=timezone.now() - timedelta(hours=25))
    output = StringIO()
    call_command("cleanup_stale_imports", stdout=output)
    assert output.getvalue() == "Expired staged CSV imports: 1\n"
    batch.refresh_from_db()
    assert batch.status == ImportBatch.Status.ABANDONED


@pytest.mark.django_db
def test_csv_import_preview_commit_is_atomic_audited_and_idempotent(
    import_context: ImportContext,
) -> None:
    content = (
        b"Date,Description,Amount,Category\n"
        b"08/21/2026,Coffee shop,-4.50,Dining\n"
        b"08/22/2026,Mystery store,-12.00,Unknown\n"
        b"08/22/2026,Paycheck,1000.00,\n"
        b"08/21/2026,Coffee shop,-4.50,Dining\n"
    )
    token = uuid.uuid4()
    batch = _stage(import_context, content, token=token)

    first_preview = _preview(import_context, batch)
    assert first_preview.ready_count == 1
    assert first_preview.category_required_count == 1
    assert first_preview.duplicate_count == 1
    assert first_preview.rejected_count == 1
    with pytest.raises(ValidationError, match="missing category"):
        commit_import_batch(
            batch=first_preview,
            actor=import_context.user,
            confirmation_token=first_preview.confirmation_token,
            request_id="csv-blocked-commit",
        )

    preview = _preview(import_context, batch, default_category=import_context.groceries)
    assert preview.ready_count == 2
    assert preview.category_required_count == 0
    result = commit_import_batch(
        batch=preview,
        actor=import_context.user,
        confirmation_token=preview.confirmation_token,
        request_id="csv-commit-request",
    )

    assert len(result.entries) == 2
    assert {entry.description for entry in result.entries} == {"Coffee shop", "Mystery store"}
    assert all(entry.provenance == JournalEntry.Provenance.IMPORTED for entry in result.entries)
    assert calculated_account_balance(import_context.checking) == Decimal("-16.50")
    preview.refresh_from_db()
    assert preview.status == ImportBatch.Status.COMMITTED
    assert preview.committed_count == 2
    assert preview.raw_deleted_at is not None
    assert all(row.raw_data == {} for row in preview.rows.all())
    assert AuditEvent.objects.filter(
        action="import.batch_uploaded", entity_id=str(batch.pk)
    ).exists()
    assert (
        AuditEvent.objects.filter(action="import.batch_previewed", entity_id=str(batch.pk)).count()
        == 2
    )
    assert AuditEvent.objects.filter(
        action="import.batch_committed", entity_id=str(batch.pk)
    ).exists()

    replay = commit_import_batch(
        batch=preview,
        actor=import_context.spouse,
        confirmation_token=preview.confirmation_token,
        request_id="csv-commit-replay",
    )
    assert replay.already_committed is True
    assert len(replay.entries) == 2
    assert JournalEntry.objects.filter(provenance=JournalEntry.Provenance.IMPORTED).count() == 2

    same_file = _stage(import_context, content, token=uuid.uuid4())
    same_submission = _stage(import_context, b"ignored", token=token)
    assert same_file.pk == preview.pk
    assert same_submission.pk == preview.pk


@pytest.mark.django_db
def test_card_csv_import_requires_period_and_builds_payment_reserve(
    import_context: ImportContext,
) -> None:
    batch = _stage(
        import_context,
        (
            b"Date,Description,Amount,Category\n"
            b"08/22/2026,Card groceries,25.00,Groceries\n"
            b"09/22/2026,Outside generated periods,10.00,Groceries\n"
        ),
        account=import_context.card,
    )
    preview = _preview(import_context, batch, expense_sign="positive")
    assert preview.ready_count == 1
    assert preview.rejected_count == 1
    rejected = preview.rows.get(status=ImportRow.Status.REJECTED)
    assert "No generated paycheck period" in rejected.rejection_reason

    result = commit_import_batch(
        batch=preview,
        actor=import_context.user,
        confirmation_token=preview.confirmation_token,
        request_id="csv-card-commit",
    )
    assert len(result.entries) == 1
    assert credit_card_payment_reserve(import_context.card) == Decimal("25.00")
    reserve = CardPaymentReserveEntry.objects.get(journal_entry=result.entries[0])
    assert reserve.amount == Decimal("25.00")
    assert reserve.pay_period.start_date == date(2026, 8, 20)


@pytest.mark.django_db
def test_import_commit_rolls_back_financial_rows_and_cleanup_if_batch_audit_fails(
    import_context: ImportContext,
) -> None:
    batch = _preview(
        import_context,
        _stage(
            import_context,
            b"Date,Description,Amount,Category\n08/22/2026,Rollback expense,-9.00,Groceries\n",
        ),
    )
    original_append = __import__("imports.services.batches", fromlist=["append_event"]).append_event

    def failing_append(*args: object, **kwargs: object) -> object:
        if kwargs.get("action") == "import.batch_committed":
            raise RuntimeError("simulated final audit failure")
        return original_append(*args, **kwargs)

    with patch("imports.services.batches.append_event", side_effect=failing_append):
        with pytest.raises(RuntimeError, match="audit failure"):
            commit_import_batch(
                batch=batch,
                actor=import_context.user,
                confirmation_token=batch.confirmation_token,
                request_id="csv-audit-rollback",
            )

    batch.refresh_from_db()
    assert batch.status == ImportBatch.Status.PREVIEWED
    assert batch.raw_deleted_at is None
    assert batch.rows.get().raw_data
    assert not JournalEntry.objects.filter(description="Rollback expense").exists()
    assert not AuditEvent.objects.filter(
        action="import.batch_committed", entity_id=str(batch.pk)
    ).exists()


@pytest.mark.django_db
def test_import_service_enforces_household_scope_and_confirmation_token(
    import_context: ImportContext,
) -> None:
    other_household = Household.objects.create(name="Other Import Household")
    HouseholdMembership.objects.create(household=other_household, user=import_context.outsider)
    other_account = create_financial_account(
        household=other_household,
        actor=import_context.outsider,
        name="Other checking",
        account_type=FinancialAccount.AccountType.CHECKING,
        classification=FinancialAccount.Classification.ASSET,
        request_id="csv-other-account",
    )
    content = b"Date,Description,Amount,Category\n08/22/2026,Scoped,-2.00,Groceries\n"
    with pytest.raises(PermissionDenied):
        stage_csv_import(
            household=import_context.household,
            actor=import_context.user,
            target_account=other_account,
            upload=_upload(content),
            submission_token=uuid.uuid4(),
            request_id="csv-cross-account",
        )

    batch = _preview(import_context, _stage(import_context, content))
    with pytest.raises(PermissionDenied):
        commit_import_batch(
            batch=batch,
            actor=import_context.outsider,
            confirmation_token=batch.confirmation_token,
            request_id="csv-cross-actor",
        )
    with pytest.raises(ValidationError, match="confirmation token"):
        commit_import_batch(
            batch=batch,
            actor=import_context.user,
            confirmation_token=uuid.uuid4(),
            request_id="csv-invalid-confirmation",
        )
    assert not JournalEntry.objects.filter(description="Scoped").exists()


@pytest.mark.django_db
def test_abandon_scrubs_raw_rows_is_idempotent_and_allows_fresh_upload(
    import_context: ImportContext,
) -> None:
    content = b"Date,Description,Amount,Category\n08/22/2026,Discard me,-3.00,Groceries\n"
    batch = _stage(import_context, content)
    abandoned = abandon_import_batch(
        batch=batch,
        actor=import_context.spouse,
        request_id="csv-abandon",
    )
    assert abandoned.status == ImportBatch.Status.ABANDONED
    assert abandoned.raw_deleted_at is not None
    assert abandoned.rows.get().raw_data == {}
    assert (
        abandon_import_batch(
            batch=abandoned,
            actor=import_context.user,
            request_id="csv-abandon-replay",
        ).pk
        == batch.pk
    )
    replacement = _stage(import_context, content)
    assert replacement.pk != batch.pk


@pytest.mark.django_db
def test_preview_detects_existing_and_post_preview_duplicates(
    import_context: ImportContext,
) -> None:
    first_content = (
        b"Date,Description,Amount,Category,Reference\n"
        b"08/22/2026,Already entered,-7.25,Groceries,first\n"
    )
    record_spending_expense(
        household=import_context.household,
        actor=import_context.user,
        account=import_context.checking,
        category=import_context.groceries,
        amount=Decimal("7.25"),
        effective_at=datetime(2026, 8, 22, 12, tzinfo=ZoneInfo("America/New_York")),
        description="  already   ENTERED ",
        request_id="csv-existing-manual",
    )
    existing_preview = _preview(import_context, _stage(import_context, first_content))
    assert existing_preview.ready_count == 0
    assert existing_preview.duplicate_count == 1

    second_content = (
        b"Date,Description,Amount,Category,Reference\n"
        b"08/23/2026,Arrived after preview,-6.00,Dining,second\n"
    )
    pending = _preview(import_context, _stage(import_context, second_content))
    assert pending.ready_count == 1
    record_spending_expense(
        household=import_context.household,
        actor=import_context.user,
        account=import_context.checking,
        category=import_context.dining,
        amount=Decimal("6.00"),
        effective_at=datetime(2026, 8, 23, 12, tzinfo=ZoneInfo("America/New_York")),
        description="Arrived after preview",
        request_id="csv-race-manual",
    )
    result = commit_import_batch(
        batch=pending,
        actor=import_context.user,
        confirmation_token=pending.confirmation_token,
        request_id="csv-race-commit",
    )
    assert result.entries == ()
    pending.refresh_from_db()
    assert pending.committed_count == 0
    assert pending.duplicate_count == 1


@pytest.mark.django_db
def test_preview_reports_normalization_errors_without_committing(
    import_context: ImportContext,
) -> None:
    long_description = "x" * 201
    content = (
        "Date,Description,Amount,Category\n"
        '2026-08-21,Parenthesized currency,"($1,234.50)",Groceries\n'
        "08-22-2026,Blank amount,0.00,Dining\n"
        "not-a-date,Bad date,-2.00,Dining\n"
        ",Missing date,-3.00,Dining\n"
        "08/22/2026,   ,-4.00,Dining\n"
        f"08/22/2026,{long_description},-5.00,Dining\n"
        "08/22/2026,Formula amount,=2+2,Dining\n"
    ).encode()
    preview = _preview(import_context, _stage(import_context, content))
    assert preview.ready_count == 1
    assert preview.rejected_count == 6
    ready = preview.rows.get(status=ImportRow.Status.READY)
    assert ready.amount == Decimal("1234.50")
    assert ready.effective_date == date(2026, 8, 21)
    reasons = " ".join(
        preview.rows.filter(status=ImportRow.Status.REJECTED).values_list(
            "rejection_reason", flat=True
        )
    )
    assert "non-zero" in reasons
    assert "selected format" in reasons
    assert "Description is missing" in reasons
    assert "exceeds 200" in reasons
    assert "supported currency" in reasons
    assert not JournalEntry.objects.filter(provenance=JournalEntry.Provenance.IMPORTED).exists()


@pytest.mark.django_db
def test_import_services_reject_invalid_lifecycle_mapping_and_scoped_fallbacks(
    import_context: ImportContext,
) -> None:
    content = b"Date,Description,Amount,Category\n08/22/2026,Validation,-2.00,Groceries\n"
    batch = _stage(import_context, content)
    with pytest.raises(ValidationError, match="Preview the CSV"):
        commit_import_batch(
            batch=batch,
            actor=import_context.user,
            confirmation_token=batch.confirmation_token,
            request_id="csv-before-preview",
        )
    invalid_mappings = (
        {
            "date_column": "Missing",
            "description_column": "Description",
            "amount_column": "Amount",
            "category_column": "Category",
        },
        {
            "date_column": "Date",
            "description_column": "Date",
            "amount_column": "Amount",
            "category_column": "Category",
        },
        {
            "date_column": "Date",
            "description_column": "Description",
            "amount_column": "Amount",
            "category_column": "Missing",
        },
        {
            "date_column": "Date",
            "description_column": "Description",
            "amount_column": "Amount",
            "category_column": "Date",
        },
    )
    for index, mapping in enumerate(invalid_mappings):
        with pytest.raises(ValidationError):
            preview_import_batch(
                batch=batch,
                actor=import_context.user,
                date_format="auto",
                expense_sign="negative",
                default_category=None,
                request_id=f"csv-invalid-mapping-{index}",
                **mapping,
            )

    other_household = Household.objects.create(name="Fallback Household")
    HouseholdMembership.objects.create(household=other_household, user=import_context.outsider)
    other_category = create_category(
        household=other_household,
        actor=import_context.outsider,
        name="Other category",
        color="#64748B",
        sort_order=0,
        request_id="csv-other-category",
    )
    with pytest.raises(PermissionDenied):
        _preview(import_context, batch, default_category=other_category)
    import_context.groceries.is_archived = True
    import_context.groceries.save(update_fields=("is_archived", "updated_at"))
    with pytest.raises(ValidationError, match="fallback category must be active"):
        _preview(import_context, batch, default_category=import_context.groceries)

    invalid_account = create_financial_account(
        household=import_context.household,
        actor=import_context.user,
        name="Unsupported liability",
        account_type=FinancialAccount.AccountType.OTHER,
        classification=FinancialAccount.Classification.LIABILITY,
        request_id="csv-invalid-liability",
    )
    with pytest.raises(ValidationError, match="asset accounts"):
        _stage(import_context, content, account=invalid_account)
    archived_account = create_financial_account(
        household=import_context.household,
        actor=import_context.user,
        name="Archived CSV account",
        account_type=FinancialAccount.AccountType.CHECKING,
        classification=FinancialAccount.Classification.ASSET,
        request_id="csv-archived-account",
    )
    archived_account = archive_financial_account(
        account=archived_account,
        actor=import_context.user,
        request_id="csv-archive-account",
        reason="Closed",
    )
    with pytest.raises(ValidationError, match="active financial account"):
        _stage(import_context, content, account=archived_account)


@pytest.mark.django_db
def test_import_commit_fails_closed_if_staged_normalized_data_is_inconsistent(
    import_context: ImportContext,
) -> None:
    content = b"Date,Description,Amount,Category\n08/22/2026,Corrupt staging,-2.00,Groceries\n"
    batch = _preview(import_context, _stage(import_context, content))
    row = batch.rows.get()
    row.amount = None
    row.save(update_fields=("amount",))
    with pytest.raises(ValidationError, match="missing normalized"):
        commit_import_batch(
            batch=batch,
            actor=import_context.user,
            confirmation_token=batch.confirmation_token,
            request_id="csv-corrupt-staging",
        )
    assert not JournalEntry.objects.filter(description="Corrupt staging").exists()


@pytest.mark.parametrize(
    ("name", "content", "message"),
    (
        ("transactions.txt", b"Date,Description,Amount\n2026-08-22,Test,-1\n", ".csv extension"),
        ("transactions.csv", b"", "empty"),
        ("transactions.csv", b"Date,Description,Amount\n\xff,Test,-1\n", "UTF-8"),
        ("transactions.csv", b"Date,Description,Amount\n2026-08-22,Te\x00st,-1\n", "binary"),
        ("transactions.csv", b"Date,Description\n2026-08-22,Test\n", "at least three"),
        ("transactions.csv", b"Date,date,Amount\n2026-08-22,Test,-1\n", "unique"),
        ("transactions.csv", b"Date,Description,Amount\n2026-08-22,Test\n", "wrong number"),
        ("transactions.csv", b'Date,Description,Amount\n2026-08-22,"broken,-1\n', "malformed"),
        ("transactions.csv", b"\xef\xbb\xbf", "header row"),
        ("transactions.csv", b"Date,Description,Amount\n\n", "transaction rows"),
        ("transactions.csv", b"Date,,Amount\n2026-08-22,Test,-1\n", "must have a header"),
    ),
)
def test_csv_parser_rejects_unsafe_or_malformed_files(
    name: str,
    content: bytes,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        parse_csv_upload(_upload(content, name=name))


def test_csv_parser_closes_rejected_uploads_before_any_staging() -> None:
    wrong_extension = _upload(b"PK\x03\x04archive", name="transactions.zip")
    invalid_content = _upload(
        b"Date,Description,Amount\n2026-08-22,Te\x00st,-1\n",
    )

    with pytest.raises(ValidationError, match=r"\.csv extension"):
        parse_csv_upload(wrong_extension)
    with pytest.raises(ValidationError, match="binary"):
        parse_csv_upload(invalid_content)

    assert wrong_extension.closed is True
    assert invalid_content.closed is True


@override_settings(CSV_IMPORT_MAX_BYTES=30)
def test_csv_parser_enforces_configured_byte_limit() -> None:
    with pytest.raises(ValidationError, match="cannot exceed"):
        parse_csv_upload(_upload(b"Date,Description,Amount\n2026-08-22,Something,-100.00\n"))


@override_settings(CSV_IMPORT_MAX_ROWS=1, CSV_IMPORT_MAX_CELL_LENGTH=10)
def test_csv_parser_enforces_row_and_cell_limits() -> None:
    with pytest.raises(ValidationError, match="more than 1 rows"):
        parse_csv_upload(_upload(b"Date,Desc,Amount\n2026-08-22,One,-1\n2026-08-23,Two,-2\n"))
    with pytest.raises(ValidationError, match="oversized value"):
        parse_csv_upload(_upload(b"Date,Desc,Amount\n2026-08-22,Too-long-value,-1\n"))


@override_settings(CSV_IMPORT_MAX_COLUMNS=3, CSV_IMPORT_MAX_CELL_LENGTH=5)
def test_csv_parser_enforces_column_and_header_limits() -> None:
    with pytest.raises(ValidationError, match="more than 3 columns"):
        parse_csv_upload(_upload(b"Date,Desc,Amt,Extra\n1,2,3,4\n"))
    with pytest.raises(ValidationError, match="header exceeds"):
        parse_csv_upload(_upload(b"LongDate,Desc,Amt\n1,2,3\n"))


@pytest.mark.django_db
def test_csv_ui_walkthrough_is_household_scoped_and_requires_confirmation(
    client: Client,
    import_context: ImportContext,
) -> None:
    _mfa_ready(import_context.user)
    client.force_login(import_context.user)
    upload_response = client.post(
        reverse("imports:upload"),
        {
            "target_account": str(import_context.checking.pk),
            "csv_file": _upload(
                b"Date,Description,Amount,Category\n08/22/2026,=FORMULA,-8.00,Groceries\n",
                name="..\\private\\statement.csv",
            ),
            "submission_token": str(uuid.uuid4()),
        },
    )
    assert upload_response.status_code == 302
    batch = ImportBatch.objects.get()
    assert batch.original_filename == "statement.csv"
    assert upload_response.headers["Location"] == reverse("imports:batch-map", args=(batch.pk,))

    map_response = client.post(
        reverse("imports:batch-map", args=(batch.pk,)),
        {
            "date_column": "Date",
            "description_column": "Description",
            "amount_column": "Amount",
            "category_column": "Category",
            "date_format": "auto",
            "expense_sign": "negative",
            "default_category": "",
        },
    )
    assert map_response.status_code == 302
    preview = client.get(reverse("imports:batch-preview", args=(batch.pk,)))
    assert preview.status_code == 200
    assert b"=FORMULA" in preview.content
    assert b"No ledger entries yet" not in preview.content

    unconfirmed = client.post(reverse("imports:batch-commit", args=(batch.pk,)), {})
    assert unconfirmed.status_code == 302
    assert not JournalEntry.objects.filter(description="=FORMULA").exists()

    batch.refresh_from_db()
    committed = client.post(
        reverse("imports:batch-commit", args=(batch.pk,)),
        {
            "confirm": "on",
            "confirmation_token": str(batch.confirmation_token),
        },
        follow=True,
    )
    assert committed.status_code == 200
    assert b"Imported 1 protected transactions" in committed.content
    entry = JournalEntry.objects.get(description="=FORMULA")
    assert entry.provenance == JournalEntry.Provenance.IMPORTED
    assert reverse("spending:transaction-detail", args=(entry.pk,)).encode() in committed.content

    other_household = Household.objects.create(name="Scoped UI Household")
    HouseholdMembership.objects.create(household=other_household, user=import_context.outsider)
    _mfa_ready(import_context.outsider)
    outsider_client = Client()
    outsider_client.force_login(import_context.outsider)
    hidden = outsider_client.get(reverse("imports:batch-preview", args=(batch.pk,)))
    assert hidden.status_code == 404


@pytest.mark.django_db
def test_csv_ui_history_mapping_errors_replays_and_abandonment(
    client: Client,
    import_context: ImportContext,
) -> None:
    _mfa_ready(import_context.user)
    client.force_login(import_context.user)
    assert client.get(reverse("imports:history")).status_code == 200
    assert client.get(reverse("imports:upload")).status_code == 200
    invalid_upload = client.post(
        reverse("imports:upload"),
        {
            "target_account": str(import_context.checking.pk),
            "csv_file": _upload(b"not csv", name="bad.txt"),
            "submission_token": str(uuid.uuid4()),
        },
    )
    assert invalid_upload.status_code == 200
    assert b".csv extension" in invalid_upload.content

    content = b"Date,Description,Amount,Category\n08/22/2026,UI branches,-2.00,Groceries\n"
    batch = _stage(import_context, content)
    uploaded_preview = client.get(reverse("imports:batch-preview", args=(batch.pk,)))
    assert uploaded_preview.status_code == 302
    assert uploaded_preview.headers["Location"] == reverse("imports:batch-map", args=(batch.pk,))
    assert client.get(reverse("imports:batch-map", args=(batch.pk,))).status_code == 200
    invalid_mapping = client.post(
        reverse("imports:batch-map", args=(batch.pk,)),
        {
            "date_column": "Date",
            "description_column": "Date",
            "amount_column": "Amount",
            "category_column": "Category",
            "date_format": "auto",
            "expense_sign": "negative",
            "default_category": "",
        },
    )
    assert invalid_mapping.status_code == 200
    assert b"must use different columns" in invalid_mapping.content

    preview = _preview(import_context, batch)
    assert client.get(reverse("imports:batch-map", args=(batch.pk,))).status_code == 200
    failed_commit = client.post(
        reverse("imports:batch-commit", args=(batch.pk,)),
        {"confirm": "on", "confirmation_token": str(uuid.uuid4())},
        follow=True,
    )
    assert b"confirmation token is invalid" in failed_commit.content
    committed = client.post(
        reverse("imports:batch-commit", args=(batch.pk,)),
        {"confirm": "on", "confirmation_token": str(preview.confirmation_token)},
    )
    assert committed.status_code == 302
    replay = client.post(
        reverse("imports:batch-commit", args=(batch.pk,)),
        {"confirm": "on", "confirmation_token": str(preview.confirmation_token)},
        follow=True,
    )
    assert b"already committed" in replay.content
    assert client.get(reverse("imports:batch-map", args=(batch.pk,))).status_code == 302
    committed_abandon = client.post(
        reverse("imports:batch-abandon", args=(batch.pk,)),
        {"confirm": "on"},
        follow=True,
    )
    assert b"committed import cannot be abandoned" in committed_abandon.content

    other = _stage(
        import_context,
        b"Date,Description,Amount,Category\n08/23/2026,Abandon UI,-3.00,Dining\n",
    )
    invalid_abandon = client.post(reverse("imports:batch-abandon", args=(other.pk,)), {})
    assert invalid_abandon.status_code == 302
    abandoned = client.post(
        reverse("imports:batch-abandon", args=(other.pk,)),
        {"confirm": "on"},
        follow=True,
    )
    assert b"raw row data was removed" in abandoned.content
    assert client.get(reverse("imports:batch-map", args=(other.pk,))).status_code == 404


@pytest.mark.django_db
def test_invalid_csv_forms_emit_minimized_security_events(
    client: Client,
    import_context: ImportContext,
    caplog: pytest.LogCaptureFixture,
) -> None:
    _mfa_ready(import_context.user)
    client.force_login(import_context.user)
    batch = _stage(
        import_context,
        b"Date,Description,Amount\n08/22/2026,Synthetic,-2.00\n",
    )
    marker = "PRIVATE_ROW_CANARY"

    with caplog.at_level(logging.WARNING, logger="security"):
        upload = client.post(reverse("imports:upload"), {"untrusted": marker})
        mapping = client.post(reverse("imports:batch-map", args=(batch.pk,)), {"untrusted": marker})
        commit = client.post(
            reverse("imports:batch-commit", args=(batch.pk,)), {"untrusted": marker}
        )
        abandon = client.post(
            reverse("imports:batch-abandon", args=(batch.pk,)), {"untrusted": marker}
        )

    assert [upload.status_code, mapping.status_code, commit.status_code, abandon.status_code] == [
        200,
        200,
        302,
        302,
    ]
    records = [
        record
        for record in caplog.records
        if getattr(record, "event", "")
        in {
            "import.upload_rejected",
            "import.preview_rejected",
            "import.commit_rejected",
            "import.abandon_rejected",
        }
    ]
    assert [record.event for record in records] == [  # type: ignore[attr-defined]
        "import.upload_rejected",
        "import.preview_rejected",
        "import.commit_rejected",
        "import.abandon_rejected",
    ]
    assert all(record.levelno == logging.WARNING for record in records)
    assert all(record.import_id == str(batch.pk) for record in records[1:])  # type: ignore[attr-defined]
    payloads = [json.loads(RedactingJsonFormatter().format(record)) for record in records]
    assert all(marker not in json.dumps(payload) for payload in payloads)
    assert all("untrusted" not in payload for payload in payloads)


@pytest.mark.django_db
def test_csv_pages_require_login_csrf_and_allowed_methods(
    client: Client,
    import_context: ImportContext,
) -> None:
    assert client.get(reverse("imports:history")).status_code == 302
    assert client.get(reverse("imports:upload")).status_code == 302
    _mfa_ready(import_context.user)
    method_client = Client()
    method_client.force_login(import_context.user)
    assert method_client.put(reverse("imports:upload"), data={}).status_code == 405
    batch = _stage(
        import_context,
        b"Date,Description,Amount,Category\n08/22/2026,Methods,-2.00,Groceries\n",
    )
    assert method_client.get(reverse("imports:batch-commit", args=(batch.pk,))).status_code == 405

    csrf_client = Client(enforce_csrf_checks=True)
    csrf_client.force_login(import_context.user)
    rejected = csrf_client.post(
        reverse("imports:upload"),
        {
            "target_account": str(import_context.checking.pk),
            "csv_file": _upload(
                b"Date,Description,Amount,Category\n08/23/2026,CSRF,-4.00,Dining\n"
            ),
            "submission_token": str(uuid.uuid4()),
        },
    )
    assert rejected.status_code == 403
    assert not ImportBatch.objects.filter(rows__description="CSRF").exists()
