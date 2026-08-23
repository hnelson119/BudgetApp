from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import date, datetime, time
from decimal import Decimal, InvalidOperation
from uuid import UUID
from zoneinfo import ZoneInfo

from django.core.exceptions import PermissionDenied, ValidationError
from django.core.files.uploadedfile import UploadedFile
from django.db import transaction
from django.db.models import QuerySet
from django.utils import timezone

from audit.services import append_event
from households.models import Category, Household
from households.services.access import require_household_membership
from identity.models import User
from imports.models import ImportBatch, ImportRow
from imports.services.parsing import parse_csv_upload
from ledger.models import FinancialAccount, JournalEntry, JournalPosting
from periods.models import PayPeriod
from spending.services import record_spending_expense

_AMOUNT_PATTERN = re.compile(r"^[+-]?(?:\d+|\d{1,3}(?:,\d{3})+)(?:\.\d{1,2})?$")
_DATE_FORMATS: dict[str, tuple[str, ...]] = {
    "auto": ("%Y-%m-%d", "%m/%d/%Y", "%m/%d/%y", "%m-%d-%Y"),
    "iso": ("%Y-%m-%d",),
    "us_slash": ("%m/%d/%Y", "%m/%d/%y"),
    "us_dash": ("%m-%d-%Y",),
}


@dataclass(frozen=True, slots=True)
class ImportCommitResult:
    batch: ImportBatch
    entries: tuple[JournalEntry, ...]
    already_committed: bool = False


def _eligible_account(account: FinancialAccount, household: Household) -> FinancialAccount:
    if account.household_id != household.pk:
        raise PermissionDenied
    if account.archived_at is not None:
        raise ValidationError("CSV imports require an active financial account.")
    if not (
        account.classification == FinancialAccount.Classification.ASSET
        or (
            account.account_type == FinancialAccount.AccountType.CREDIT_CARD
            and account.classification == FinancialAccount.Classification.LIABILITY
        )
    ):
        raise ValidationError("CSV imports support asset accounts and credit-card liabilities.")
    return account


def _active_category(category: Category | None, household: Household) -> Category | None:
    if category is None:
        return None
    if category.household_id != household.pk:
        raise PermissionDenied
    if category.is_archived:
        raise ValidationError("The fallback category must be active.")
    return category


def _description(value: str) -> str:
    normalized = " ".join(value.split())
    if not normalized:
        raise ValidationError("Description is missing.")
    if len(normalized) > 200:
        raise ValidationError("Description exceeds 200 characters.")
    return normalized


def _transaction_date(value: str, date_format: str) -> date:
    formats = _DATE_FORMATS.get(date_format)
    if formats is None:
        raise ValidationError("The selected date format is invalid.")
    normalized = value.strip()
    for pattern in formats:
        try:
            return datetime.strptime(normalized, pattern).date()
        except ValueError:
            continue
    raise ValidationError("Date does not match the selected format.")


def _signed_amount(value: str) -> Decimal:
    normalized = value.strip()
    parenthesized = normalized.startswith("(") and normalized.endswith(")")
    if parenthesized:
        normalized = normalized[1:-1].strip()
    if normalized.startswith("$"):
        normalized = normalized[1:].strip()
    if not _AMOUNT_PATTERN.fullmatch(normalized):
        raise ValidationError("Amount is not a supported currency value.")
    try:
        amount = Decimal(normalized.replace(",", ""))
    except InvalidOperation as error:
        raise ValidationError("Amount is not a supported currency value.") from error
    if parenthesized:
        amount = -amount
    if not amount.is_finite() or amount == Decimal("0.00"):
        raise ValidationError("Amount must be non-zero.")
    return amount


def _expense_amount(value: str, expense_sign: str) -> Decimal:
    signed = _signed_amount(value)
    if expense_sign == "negative" and signed >= 0:
        raise ValidationError("Non-expense credit or income row excluded.")
    if expense_sign == "positive" and signed <= 0:
        raise ValidationError("Non-expense credit or refund row excluded.")
    if expense_sign not in {"negative", "positive", "absolute"}:
        raise ValidationError("The selected expense-sign rule is invalid.")
    return abs(signed)


def _fingerprint(
    *,
    account: FinancialAccount,
    effective_date: date,
    amount: Decimal,
    description: str,
) -> str:
    normalized_description = " ".join(description.split()).casefold()
    payload = "\x1f".join(
        (
            str(account.pk),
            effective_date.isoformat(),
            f"{amount:.2f}",
            normalized_description,
        )
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _existing_fingerprints(
    household: Household,
    account: FinancialAccount,
    dates: set[date],
) -> set[str]:
    if not dates:
        return set()
    zone = ZoneInfo(household.time_zone)
    start = datetime.combine(min(dates), time.min, tzinfo=zone)
    end = datetime.combine(max(dates), time.max, tzinfo=zone)
    postings = JournalPosting.objects.filter(
        entry__household=household,
        entry__entry_type=JournalEntry.EntryType.EXPENSE,
        entry__effective_at__gte=start,
        entry__effective_at__lte=end,
        financial_account=account,
        side=JournalPosting.Side.CREDIT,
    ).select_related("entry")
    return {
        _fingerprint(
            account=account,
            effective_date=timezone.localtime(posting.entry.effective_at, zone).date(),
            amount=posting.amount,
            description=posting.entry.description,
        )
        for posting in postings
    }


def _category_lookup(household: Household) -> dict[str, Category]:
    return {
        category.name.casefold(): category
        for category in Category.objects.filter(household=household, is_archived=False)
    }


def _available_periods(household: Household, account: FinancialAccount) -> tuple[PayPeriod, ...]:
    if account.account_type != FinancialAccount.AccountType.CREDIT_CARD:
        return ()
    return tuple(PayPeriod.objects.filter(household=household).order_by("start_date"))


def _date_has_period(value: date, periods: tuple[PayPeriod, ...]) -> bool:
    return any(period.start_date <= value < period.next_start_date for period in periods)


def _error_message(error: ValidationError) -> str:
    return error.messages[0] if error.messages else "Row validation failed."


def _batch_rows(batch: ImportBatch) -> QuerySet[ImportRow]:
    return batch.rows.select_related("category", "journal_entry").order_by("row_number")


def stage_csv_import(
    *,
    household: Household,
    actor: User,
    target_account: FinancialAccount,
    upload: UploadedFile,
    submission_token: UUID,
    request_id: str,
) -> ImportBatch:
    require_household_membership(actor, household)
    target_account = _eligible_account(target_account, household)
    existing_submission = ImportBatch.objects.filter(submission_token=submission_token).first()
    if existing_submission is not None:
        upload.close()
        if existing_submission.household_id != household.pk:
            raise PermissionDenied
        return existing_submission
    parsed = parse_csv_upload(upload)
    existing_file = (
        ImportBatch.objects.filter(
            household=household,
            target_account=target_account,
            file_checksum=parsed.checksum,
        )
        .exclude(status=ImportBatch.Status.ABANDONED)
        .first()
    )
    if existing_file is not None:
        return existing_file

    with transaction.atomic():
        locked_account = FinancialAccount.objects.select_for_update().get(pk=target_account.pk)
        target_account = _eligible_account(locked_account, household)
        concurrent_file = (
            ImportBatch.objects.filter(
                household=household,
                target_account=target_account,
                file_checksum=parsed.checksum,
            )
            .exclude(status=ImportBatch.Status.ABANDONED)
            .first()
        )
        if concurrent_file is not None:
            return concurrent_file
        batch = ImportBatch.objects.create(
            household=household,
            created_by=actor,
            target_account=target_account,
            original_filename=parsed.filename,
            file_checksum=parsed.checksum,
            submission_token=submission_token,
            headers=list(parsed.headers),
            staged_count=len(parsed.rows),
        )
        ImportRow.objects.bulk_create(
            [
                ImportRow(
                    batch=batch,
                    row_number=row.row_number,
                    raw_data=row.values,
                )
                for row in parsed.rows
            ]
        )
        append_event(
            household=household,
            actor=actor,
            action="import.batch_uploaded",
            entity_type="import_batch",
            entity_id=batch.pk,
            request_id=request_id,
            after={
                "target_account_id": target_account.pk,
                "file_checksum": parsed.checksum,
                "staged_count": len(parsed.rows),
            },
        )
        return batch


@transaction.atomic
def preview_import_batch(
    *,
    batch: ImportBatch,
    actor: User,
    date_column: str,
    description_column: str,
    amount_column: str,
    category_column: str,
    date_format: str,
    expense_sign: str,
    default_category: Category | None,
    request_id: str,
) -> ImportBatch:
    locked = (
        ImportBatch.objects.select_for_update()
        .select_related("household", "target_account")
        .get(pk=batch.pk)
    )
    require_household_membership(actor, locked.household)
    if locked.status not in {ImportBatch.Status.UPLOADED, ImportBatch.Status.PREVIEWED}:
        raise ValidationError("Only an uploaded import can be mapped and previewed.")
    account = _eligible_account(locked.target_account, locked.household)
    default_category = _active_category(default_category, locked.household)
    headers = {str(header) for header in locked.headers}
    required_columns = (date_column, description_column, amount_column)
    if any(column not in headers for column in required_columns):
        raise ValidationError("Select columns that exist in the uploaded CSV.")
    if len(set(required_columns)) != len(required_columns):
        raise ValidationError("Date, description, and amount must use different columns.")
    if category_column and category_column not in headers:
        raise ValidationError("The selected category column does not exist in the uploaded CSV.")
    if category_column in required_columns:
        raise ValidationError("The category must use a different column.")

    rows = list(_batch_rows(locked))
    categories = _category_lookup(locked.household)
    periods = _available_periods(locked.household, account)
    requires_period = account.account_type == FinancialAccount.AccountType.CREDIT_CARD
    candidate_dates: set[date] = set()
    normalized: dict[int, tuple[date, str, Decimal, Category | None, str]] = {}
    for row in rows:
        row.effective_date = None
        row.description = ""
        row.amount = None
        row.category = None
        row.fingerprint = ""
        row.rejection_reason = ""
        row.status = ImportRow.Status.REJECTED
        try:
            effective_date = _transaction_date(row.raw_data[date_column], date_format)
            description = _description(row.raw_data[description_column])
            amount = _expense_amount(row.raw_data[amount_column], expense_sign)
            category_name = row.raw_data.get(category_column, "").strip() if category_column else ""
            category = categories.get(category_name.casefold()) if category_name else None
            category = category or default_category
            fingerprint = _fingerprint(
                account=account,
                effective_date=effective_date,
                amount=amount,
                description=description,
            )
            if requires_period and not _date_has_period(effective_date, periods):
                raise ValidationError("No generated paycheck period contains this card purchase.")
        except (KeyError, ValidationError) as error:
            if isinstance(error, KeyError):
                row.rejection_reason = "A mapped column is missing from this row."
            else:
                row.rejection_reason = _error_message(error)
            continue
        normalized[row.pk] = (effective_date, description, amount, category, fingerprint)
        candidate_dates.add(effective_date)

    existing = _existing_fingerprints(locked.household, account, candidate_dates)
    seen = set(existing)
    for row in rows:
        values = normalized.get(row.pk)
        if values is None:
            continue
        effective_date, description, amount, category, fingerprint = values
        row.effective_date = effective_date
        row.description = description
        row.amount = amount
        row.category = category
        row.fingerprint = fingerprint
        if fingerprint in seen:
            row.status = ImportRow.Status.DUPLICATE
            row.rejection_reason = "A matching transaction already exists."
        elif category is None:
            row.status = ImportRow.Status.CATEGORY_REQUIRED
            row.rejection_reason = "Choose a fallback category before importing this row."
        else:
            row.status = ImportRow.Status.READY
        seen.add(fingerprint)

    ImportRow.objects.bulk_update(
        rows,
        (
            "effective_date",
            "description",
            "amount",
            "category",
            "fingerprint",
            "status",
            "rejection_reason",
        ),
    )
    locked.mapping = {
        "date_column": date_column,
        "description_column": description_column,
        "amount_column": amount_column,
        "category_column": category_column,
        "date_format": date_format,
        "expense_sign": expense_sign,
        "default_category_id": str(default_category.pk) if default_category else "",
    }
    locked.status = ImportBatch.Status.PREVIEWED
    locked.ready_count = sum(row.status == ImportRow.Status.READY for row in rows)
    locked.duplicate_count = sum(row.status == ImportRow.Status.DUPLICATE for row in rows)
    locked.category_required_count = sum(
        row.status == ImportRow.Status.CATEGORY_REQUIRED for row in rows
    )
    locked.rejected_count = sum(row.status == ImportRow.Status.REJECTED for row in rows)
    locked.previewed_at = timezone.now()
    locked.save(
        update_fields=(
            "mapping",
            "status",
            "ready_count",
            "duplicate_count",
            "category_required_count",
            "rejected_count",
            "previewed_at",
        )
    )
    append_event(
        household=locked.household,
        actor=actor,
        action="import.batch_previewed",
        entity_type="import_batch",
        entity_id=locked.pk,
        request_id=request_id,
        after={
            "target_account_id": account.pk,
            "staged_count": locked.staged_count,
            "ready_count": locked.ready_count,
            "duplicate_count": locked.duplicate_count,
            "category_required_count": locked.category_required_count,
            "rejected_count": locked.rejected_count,
        },
    )
    return locked


@transaction.atomic
def commit_import_batch(
    *,
    batch: ImportBatch,
    actor: User,
    confirmation_token: UUID,
    request_id: str,
) -> ImportCommitResult:
    locked = (
        ImportBatch.objects.select_for_update()
        .select_related("household", "target_account")
        .get(pk=batch.pk)
    )
    require_household_membership(actor, locked.household)
    if confirmation_token != locked.confirmation_token:
        raise ValidationError("The import confirmation token is invalid.")
    if locked.status == ImportBatch.Status.COMMITTED:
        existing_entries = tuple(
            JournalEntry.objects.filter(import_row__batch=locked).order_by("effective_at", "pk")
        )
        return ImportCommitResult(locked, existing_entries, already_committed=True)
    if locked.status != ImportBatch.Status.PREVIEWED:
        raise ValidationError("Preview the CSV before confirming its import.")
    if locked.category_required_count:
        raise ValidationError("Resolve every missing category before confirming the import.")
    account = FinancialAccount.objects.select_for_update().get(pk=locked.target_account_id)
    account = _eligible_account(account, locked.household)
    rows = list(_batch_rows(locked))
    ready_rows = [row for row in rows if row.status == ImportRow.Status.READY]
    candidate_dates = {row.effective_date for row in ready_rows if row.effective_date is not None}
    fingerprints = _existing_fingerprints(locked.household, account, candidate_dates)
    entries: list[JournalEntry] = []
    now = timezone.now()
    zone = ZoneInfo(locked.household.time_zone)
    for row in ready_rows:
        if row.fingerprint in fingerprints:
            row.status = ImportRow.Status.DUPLICATE
            row.rejection_reason = "A matching transaction was committed after this preview."
            continue
        if row.effective_date is None or row.amount is None or row.category is None:
            raise ValidationError("A ready import row is missing normalized transaction data.")
        entry = record_spending_expense(
            household=locked.household,
            actor=actor,
            account=account,
            category=row.category,
            amount=row.amount,
            effective_at=datetime.combine(row.effective_date, time(hour=12), tzinfo=zone),
            description=row.description,
            request_id=request_id,
            provenance=JournalEntry.Provenance.IMPORTED,
            idempotency_key=f"csv-{locked.pk.hex}-{row.row_number}",
        )
        row.status = ImportRow.Status.COMMITTED
        row.journal_entry = entry
        row.rejection_reason = ""
        fingerprints.add(row.fingerprint)
        entries.append(entry)

    for row in rows:
        row.raw_data = {}
    ImportRow.objects.bulk_update(
        rows,
        ("status", "rejection_reason", "journal_entry", "raw_data"),
    )
    locked.status = ImportBatch.Status.COMMITTED
    locked.ready_count = sum(row.status == ImportRow.Status.COMMITTED for row in rows)
    locked.duplicate_count = sum(row.status == ImportRow.Status.DUPLICATE for row in rows)
    locked.committed_count = len(entries)
    locked.completed_at = now
    locked.raw_deleted_at = now
    locked.save(
        update_fields=(
            "status",
            "ready_count",
            "duplicate_count",
            "committed_count",
            "completed_at",
            "raw_deleted_at",
        )
    )
    append_event(
        household=locked.household,
        actor=actor,
        action="import.batch_committed",
        entity_type="import_batch",
        entity_id=locked.pk,
        request_id=request_id,
        after={
            "target_account_id": account.pk,
            "committed_count": locked.committed_count,
            "duplicate_count": locked.duplicate_count,
            "rejected_count": locked.rejected_count,
            "raw_data_deleted": True,
        },
    )
    return ImportCommitResult(locked, tuple(entries))


@transaction.atomic
def abandon_import_batch(
    *,
    batch: ImportBatch,
    actor: User,
    request_id: str,
) -> ImportBatch:
    locked = ImportBatch.objects.select_for_update().select_related("household").get(pk=batch.pk)
    require_household_membership(actor, locked.household)
    if locked.status == ImportBatch.Status.COMMITTED:
        raise ValidationError("A committed import cannot be abandoned.")
    if locked.status == ImportBatch.Status.ABANDONED:
        return locked
    now = timezone.now()
    ImportRow.objects.filter(batch=locked).update(raw_data={})
    locked.status = ImportBatch.Status.ABANDONED
    locked.completed_at = now
    locked.raw_deleted_at = now
    locked.save(update_fields=("status", "completed_at", "raw_deleted_at"))
    append_event(
        household=locked.household,
        actor=actor,
        action="import.batch_abandoned",
        entity_type="import_batch",
        entity_id=locked.pk,
        request_id=request_id,
        after={"raw_data_deleted": True},
        reason="User abandoned staged import",
    )
    return locked
