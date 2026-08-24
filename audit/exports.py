from __future__ import annotations

import csv
import json
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime

from spending.services.exports import formula_safe_text

CSV_HEADERS = (
    "sequence",
    "occurred_at",
    "household_timezone",
    "person",
    "action",
    "record_type",
    "record_id",
    "before",
    "after",
    "reason",
    "request_id",
    "previous_hash",
    "event_hash",
)


@dataclass(frozen=True, slots=True)
class AuditCSVRow:
    sequence: int
    occurred_at: datetime
    household_timezone: str
    actor_label: str
    action: str
    entity_type: str
    entity_id: str
    before: dict[str, object]
    after: dict[str, object]
    reason: str
    request_id: str
    previous_hash: str
    event_hash: str


class _CSVBuffer:
    def write(self, value: str) -> str:
        return value


def _json(value: dict[str, object]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def stream_audit_csv(rows: Iterable[AuditCSVRow]) -> Iterator[str]:
    writer = csv.writer(_CSVBuffer(), lineterminator="\r\n")
    yield writer.writerow(CSV_HEADERS)
    for row in rows:
        yield writer.writerow(
            (
                row.sequence,
                row.occurred_at.isoformat(),
                formula_safe_text(row.household_timezone),
                formula_safe_text(row.actor_label),
                formula_safe_text(row.action),
                formula_safe_text(row.entity_type),
                formula_safe_text(row.entity_id),
                formula_safe_text(_json(row.before)),
                formula_safe_text(_json(row.after)),
                formula_safe_text(row.reason),
                formula_safe_text(row.request_id),
                row.previous_hash,
                row.event_hash,
            )
        )
