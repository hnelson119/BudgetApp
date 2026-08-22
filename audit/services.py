from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import connection, transaction
from django.utils import timezone

from audit.models import ZERO_HASH, AuditEvent, AuditHead
from households.models import Household, HouseholdMembership
from identity.models import User

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$")
_SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "password",
    "password_hash",
    "recovery_code",
    "secret",
    "session",
    "session_id",
    "token",
    "totp",
}


@dataclass(frozen=True)
class AuditIntegrityResult:
    valid: bool
    event_count: int
    chain_head: str
    failure_sequence: int | None = None


def _normalize(value: Any, path: tuple[str, ...] = ()) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        raise ValidationError(f"Floating-point audit values are prohibited at {'.'.join(path)}.")
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, datetime):
        if timezone.is_naive(value):
            raise ValidationError(f"Naive audit timestamps are prohibited at {'.'.join(path)}.")
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for raw_key in sorted(value):
            if not isinstance(raw_key, str):
                raise ValidationError("Audit payload keys must be strings.")
            key = raw_key.strip()
            if key.casefold() in _SENSITIVE_KEYS:
                raise ValidationError(f"Sensitive field {key!r} is prohibited in audit payloads.")
            normalized[key] = _normalize(value[raw_key], (*path, key))
        return normalized
    if isinstance(value, (list, tuple)):
        return [_normalize(item, (*path, str(index))) for index, item in enumerate(value)]
    raise ValidationError(f"Unsupported audit value type at {'.'.join(path)}.")


def _canonical_bytes(event: AuditEvent) -> bytes:
    body = {
        "version": 1,
        "sequence": event.sequence,
        "id": str(event.id),
        "household_id": str(event.household_id),
        "actor_id": str(event.actor_id) if event.actor_id else None,
        "occurred_at": _normalize(event.occurred_at),
        "household_timezone": event.household_timezone,
        "action": event.action,
        "entity_type": event.entity_type,
        "entity_id": event.entity_id,
        "before": event.before_payload,
        "after": event.after_payload,
        "reason": event.reason,
        "request_id": event.request_id,
        "previous_hash": event.previous_hash,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _event_hash(event: AuditEvent) -> str:
    return hashlib.sha256(_canonical_bytes(event)).hexdigest()


def _append_with_postgresql_function(event: AuditEvent) -> AuditEvent:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT budget_audit.append_event(
                %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s::jsonb, %s::jsonb, %s, %s, %s, %s
            )
            """,
            [
                event.sequence,
                event.id,
                event.household_id,
                event.actor_id,
                event.occurred_at,
                event.household_timezone,
                event.action,
                event.entity_type,
                event.entity_id,
                json.dumps(event.before_payload, sort_keys=True, separators=(",", ":")),
                json.dumps(event.after_payload, sort_keys=True, separators=(",", ":")),
                event.reason,
                event.request_id,
                event.previous_hash,
                event.event_hash,
            ],
        )
    return AuditEvent.objects.get(pk=event.pk)


@transaction.atomic
def append_event(
    *,
    household: Household,
    actor: User | None,
    action: str,
    entity_type: str,
    entity_id: str | uuid.UUID,
    request_id: str,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    reason: str = "",
) -> AuditEvent:
    if not _SAFE_NAME.fullmatch(action) or not _SAFE_NAME.fullmatch(entity_type):
        raise ValidationError("Audit action and entity type must use the safe identifier format.")
    if not _SAFE_REQUEST_ID.fullmatch(request_id):
        raise ValidationError("Audit request ID is invalid.")
    entity_identifier = str(entity_id)
    if not entity_identifier or len(entity_identifier) > 64:
        raise ValidationError("Audit entity ID is invalid.")
    if len(reason) > 500:
        raise ValidationError("Audit reason is too long.")
    if (
        actor is not None
        and not HouseholdMembership.objects.filter(
            household=household,
            user=actor,
            is_active=True,
        ).exists()
    ):
        raise PermissionDenied("The audit actor is not an active household member.")

    locked_household = Household.objects.select_for_update().get(pk=household.pk)
    head = AuditHead.objects.filter(household=locked_household).first()
    sequence = 1 if head is None else head.last_sequence + 1
    previous_hash = ZERO_HASH if head is None else head.chain_head
    event = AuditEvent(
        sequence=sequence,
        household=locked_household,
        actor=actor,
        occurred_at=timezone.now(),
        household_timezone=locked_household.time_zone,
        action=action,
        entity_type=entity_type,
        entity_id=entity_identifier,
        before_payload=_normalize(before or {}),
        after_payload=_normalize(after or {}),
        reason=reason,
        request_id=request_id,
        previous_hash=previous_hash,
        event_hash=ZERO_HASH,
    )
    event.event_hash = _event_hash(event)

    if connection.vendor == "postgresql":
        return _append_with_postgresql_function(event)

    if head is None:
        head = AuditHead.objects.create(household=locked_household)
    event._append_authorized = True  # type: ignore[attr-defined]
    event.save()

    head.last_sequence = sequence
    head.event_count += 1
    head.chain_head = event.event_hash
    head.verified_at = None
    head.save(
        update_fields=("last_sequence", "event_count", "chain_head", "verified_at", "updated_at")
    )
    return event


def verify_household_chain(household: Household) -> AuditIntegrityResult:
    expected_previous_hash = ZERO_HASH
    expected_sequence = 1
    event_count = 0

    for event in AuditEvent.objects.filter(household=household).order_by("sequence"):
        if event.sequence != expected_sequence or event.previous_hash != expected_previous_hash:
            return AuditIntegrityResult(
                valid=False,
                event_count=event_count,
                chain_head=expected_previous_hash,
                failure_sequence=event.sequence,
            )
        if event.event_hash != _event_hash(event):
            return AuditIntegrityResult(
                valid=False,
                event_count=event_count,
                chain_head=expected_previous_hash,
                failure_sequence=event.sequence,
            )
        event_count += 1
        expected_sequence += 1
        expected_previous_hash = event.event_hash

    head = AuditHead.objects.filter(household=household).first()
    if head is None and event_count == 0:
        return AuditIntegrityResult(valid=True, event_count=0, chain_head=ZERO_HASH)
    head_matches = (
        head is not None
        and head.last_sequence == event_count
        and head.event_count == event_count
        and head.chain_head == expected_previous_hash
    )
    return AuditIntegrityResult(
        valid=head_matches,
        event_count=event_count,
        chain_head=expected_previous_hash,
        failure_sequence=None if head_matches else expected_sequence,
    )
