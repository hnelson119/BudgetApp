from __future__ import annotations

import csv
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from uuid import UUID

CSV_HEADERS = (
    "transaction_id",
    "effective_date",
    "effective_time",
    "time_zone",
    "description",
    "type",
    "account",
    "category",
    "amount",
    "currency",
    "status",
    "provenance",
    "note",
    "receipt_reference",
    "created_by",
    "committed_at",
    "reversal_of_id",
    "adjustment_for_id",
)
_FORMULA_PREFIXES = ("=", "+", "-", "@")


@dataclass(frozen=True, slots=True)
class TransactionCSVRow:
    transaction_id: UUID
    effective_at: datetime
    time_zone: str
    description: str
    entry_type: str
    account: str
    category: str
    amount: Decimal
    currency: str
    status: str
    provenance: str
    note: str
    receipt_reference: str
    created_by: str
    committed_at: datetime
    reversal_of_id: UUID | None
    adjustment_for_id: UUID | None


class _CSVBuffer:
    """Provide csv.writer's file interface while returning each encoded row immediately."""

    def write(self, value: str) -> str:
        return value


def formula_safe_text(value: str) -> str:
    """Force spreadsheet-formula-like text to remain literal text when a CSV is opened."""

    candidate = value.lstrip()
    if candidate.startswith(_FORMULA_PREFIXES):
        return f"'{value}"
    return value


def _identifier(value: UUID | None) -> str:
    return str(value) if value is not None else ""


def _values(row: TransactionCSVRow) -> tuple[str, ...]:
    return (
        str(row.transaction_id),
        row.effective_at.date().isoformat(),
        row.effective_at.time().isoformat(timespec="seconds"),
        formula_safe_text(row.time_zone),
        formula_safe_text(row.description),
        formula_safe_text(row.entry_type),
        formula_safe_text(row.account),
        formula_safe_text(row.category),
        format(row.amount, ".2f"),
        formula_safe_text(row.currency),
        formula_safe_text(row.status),
        formula_safe_text(row.provenance),
        formula_safe_text(row.note),
        formula_safe_text(row.receipt_reference),
        formula_safe_text(row.created_by),
        row.committed_at.isoformat(timespec="seconds"),
        _identifier(row.reversal_of_id),
        _identifier(row.adjustment_for_id),
    )


def stream_transaction_csv(rows: Iterable[TransactionCSVRow]) -> Iterator[str]:
    """Yield a CSV without retaining an export file or the complete dataset in memory."""

    writer = csv.writer(_CSVBuffer(), lineterminator="\r\n")
    yield writer.writerow(CSV_HEADERS)
    for row in rows:
        yield writer.writerow(_values(row))
