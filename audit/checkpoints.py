from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.utils import timezone

from audit.models import AuditCheckpoint, AuditHead
from audit.services import verify_household_chain
from households.models import Household

_SAFE_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


@dataclass(frozen=True)
class CheckpointWriteResult:
    checkpoint: AuditCheckpoint
    external_path: Path


def _checkpoint_body(checkpoint: AuditCheckpoint) -> dict[str, Any]:
    return {
        "version": 1,
        "id": str(checkpoint.pk),
        "household_id": str(checkpoint.household_id),
        "last_sequence": checkpoint.last_sequence,
        "event_count": checkpoint.event_count,
        "chain_head": checkpoint.chain_head,
        "verified_at": checkpoint.verified_at.isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        ),
        "external_copied_at": checkpoint.external_copied_at.isoformat(
            timespec="microseconds"
        ).replace("+00:00", "Z"),
    }


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _sign(body: dict[str, Any], signing_key: bytes) -> str:
    return hmac.new(signing_key, _canonical_json(body), hashlib.sha256).hexdigest()


def verify_checkpoint_document(document: dict[str, Any], signing_key: bytes) -> bool:
    checkpoint = document.get("checkpoint")
    signature = document.get("signature")
    if not isinstance(checkpoint, dict) or not isinstance(signature, dict):
        return False
    provided = signature.get("value")
    if signature.get("algorithm") != "HMAC-SHA256" or not isinstance(provided, str):
        return False
    expected = _sign(checkpoint, signing_key)
    return hmac.compare_digest(expected, provided)


def _checkpoint_directory(path: Path) -> Path:
    if not path.is_absolute():
        raise ValidationError("The audit checkpoint directory must be absolute.")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ValidationError("The audit checkpoint directory is unavailable.") from error
    if not resolved.is_dir():
        raise ValidationError("The audit checkpoint destination is not a directory.")
    return resolved


def _write_external_document(path: Path, document: dict[str, Any]) -> None:
    temporary_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    payload = _canonical_json(document) + b"\n"
    file_descriptor: int | None = None
    try:
        file_descriptor = os.open(
            temporary_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(file_descriptor, "wb") as destination:
            file_descriptor = None
            destination.write(payload)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary_path, path)
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        temporary_path.unlink(missing_ok=True)


def _record_postgresql_checkpoint(checkpoint: AuditCheckpoint) -> AuditCheckpoint:
    with connection.cursor() as cursor:
        cursor.execute(
            """
            SELECT budget_audit.record_checkpoint(
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            """,
            [
                checkpoint.pk,
                checkpoint.household_id,
                checkpoint.last_sequence,
                checkpoint.event_count,
                checkpoint.chain_head,
                checkpoint.verified_at,
                checkpoint.signature_algorithm,
                checkpoint.signing_key_id,
                checkpoint.signature,
                checkpoint.external_copy_name,
                checkpoint.external_copied_at,
            ],
        )
    return AuditCheckpoint.objects.get(pk=checkpoint.pk)


@transaction.atomic
def write_household_checkpoint(
    *,
    household: Household,
    directory: Path,
    signing_key: bytes,
    signing_key_id: str,
) -> CheckpointWriteResult:
    if len(signing_key) < 32:
        raise ValidationError("The audit checkpoint signing key is too short.")
    if not _SAFE_KEY_ID.fullmatch(signing_key_id):
        raise ValidationError("The audit checkpoint signing key ID is invalid.")
    destination = _checkpoint_directory(directory)
    integrity = verify_household_chain(household)
    if not integrity.valid or integrity.event_count == 0:
        raise ValidationError("The household audit chain is empty or failed verification.")

    verified_at = timezone.now()
    timestamp = verified_at.strftime("%Y%m%dT%H%M%S.%fZ")
    file_name = f"audit-{household.pk}-{timestamp}-sequence-{integrity.event_count}.checkpoint.json"
    checkpoint = AuditCheckpoint(
        household_id=household.pk,
        last_sequence=integrity.event_count,
        event_count=integrity.event_count,
        chain_head=integrity.chain_head,
        verified_at=verified_at,
        signature_algorithm="HMAC-SHA256",
        signing_key_id=signing_key_id,
        signature="",
        external_copy_name=file_name,
        external_copied_at=verified_at,
    )
    body = _checkpoint_body(checkpoint)
    checkpoint.signature = _sign(body, signing_key)
    document = {
        "checkpoint": body,
        "signature": {
            "algorithm": checkpoint.signature_algorithm,
            "key_id": checkpoint.signing_key_id,
            "value": checkpoint.signature,
        },
    }
    external_path = destination / file_name
    _write_external_document(external_path, document)

    if connection.vendor == "postgresql":
        checkpoint = _record_postgresql_checkpoint(checkpoint)
    else:
        checkpoint._append_authorized = True  # type: ignore[attr-defined]
        checkpoint.save()
        AuditHead.objects.filter(household_id=household.pk).update(verified_at=verified_at)
    return CheckpointWriteResult(checkpoint=checkpoint, external_path=external_path)
