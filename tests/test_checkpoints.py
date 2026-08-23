import json
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest
from django.core.exceptions import ValidationError
from django.core.management import call_command

import audit.checkpoints as checkpoint_services
from audit.checkpoints import verify_checkpoint_document, write_household_checkpoint
from audit.models import AuditCheckpoint, AuditHead
from audit.services import append_event
from households.models import Household, HouseholdMembership
from identity.models import User

TEST_PASSWORD = "checkpoint-test-password"  # pragma: allowlist secret
SIGNING_KEY = b"checkpoint-test-key-material-which-is-long-enough"


@pytest.fixture
def checkpoint_household(db):  # type: ignore[no-untyped-def]
    household = Household.objects.create(name="Checkpoint Household")
    user = User.objects.create_user(email="checkpoint@example.com", password=TEST_PASSWORD)
    HouseholdMembership.objects.create(household=household, user=user)
    append_event(
        household=household,
        actor=user,
        action="household.created",
        entity_type="household",
        entity_id=household.pk,
        request_id="checkpoint-request-1234",
    )
    return household


@pytest.mark.django_db
def test_checkpoint_is_signed_copied_and_immutable(
    checkpoint_household,
    tmp_path: Path,
) -> None:  # type: ignore[no-untyped-def]
    result = write_household_checkpoint(
        household=checkpoint_household,
        directory=tmp_path,
        signing_key=SIGNING_KEY,
        signing_key_id="test-key-v1",
    )

    document = json.loads(result.external_path.read_text(encoding="utf-8"))
    assert verify_checkpoint_document(document, SIGNING_KEY) is True
    assert document["checkpoint"]["chain_head"] == result.checkpoint.chain_head
    assert document["signature"]["value"] == result.checkpoint.signature
    assert AuditHead.objects.get(household=checkpoint_household).verified_at is not None

    with pytest.raises(ValidationError, match="cannot be updated"):
        AuditCheckpoint.objects.filter(pk=result.checkpoint.pk).update(signature="0" * 64)
    with pytest.raises(ValidationError, match="cannot be deleted"):
        result.checkpoint.delete()


@pytest.mark.django_db
def test_checkpoint_rejects_tampered_chain(checkpoint_household, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    from django.db import connection

    table_name = connection.ops.quote_name("audit_auditevent")
    with connection.cursor() as cursor:
        cursor.execute(f"UPDATE {table_name} SET action = %s", ["tampered.action"])

    with pytest.raises(ValidationError, match="failed verification"):
        write_household_checkpoint(
            household=checkpoint_household,
            directory=tmp_path,
            signing_key=SIGNING_KEY,
            signing_key_id="test-key-v1",
        )
    assert list(tmp_path.iterdir()) == []
    assert AuditCheckpoint.objects.count() == 0


@pytest.mark.django_db
def test_checkpoint_command_reads_signing_key_from_file_only(
    checkpoint_household,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # type: ignore[no-untyped-def]
    key_path = tmp_path / "checkpoint_signing_key"
    key_path.write_text(SIGNING_KEY.decode(), encoding="utf-8")
    destination = tmp_path / "external"
    destination.mkdir()
    monkeypatch.delenv("AUDIT_CHECKPOINT_SIGNING_KEY", raising=False)
    monkeypatch.setenv("AUDIT_CHECKPOINT_SIGNING_KEY_FILE", str(key_path))
    monkeypatch.setenv("AUDIT_CHECKPOINT_DIRECTORY", str(destination))
    monkeypatch.setenv("AUDIT_CHECKPOINT_KEY_ID", "test-key-v1")
    output = StringIO()

    call_command("write_audit_checkpoints", stdout=output)

    assert AuditCheckpoint.objects.filter(household=checkpoint_household).count() == 1
    checkpoint_files = list(destination.glob("*.checkpoint.json"))
    assert len(checkpoint_files) == 1
    assert "Wrote protected checkpoint" in output.getvalue()

    verification_output = StringIO()
    call_command(
        "verify_audit_checkpoint",
        checkpoint_files[0].name,
        stdout=verification_output,
    )
    assert "signature and database head match" in verification_output.getvalue()


def test_checkpoint_document_signature_detects_external_tampering() -> None:
    document = {
        "checkpoint": {"version": 1, "event_count": 2},
        "signature": {
            "algorithm": "HMAC-SHA256",
            "key_id": "test-key-v1",
            "value": "0" * 64,
        },
    }

    assert verify_checkpoint_document(document, SIGNING_KEY) is False


def test_checkpoint_document_rejects_malformed_envelopes() -> None:
    assert verify_checkpoint_document({}, SIGNING_KEY) is False
    assert (
        verify_checkpoint_document(
            {
                "checkpoint": {},
                "signature": {"algorithm": "SHA256", "value": 123},
            },
            SIGNING_KEY,
        )
        is False
    )


def test_checkpoint_destination_validation_and_failed_write_cleanup(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="must be absolute"):
        checkpoint_services._checkpoint_directory(Path("relative/checkpoints"))
    with pytest.raises(ValidationError, match="unavailable"):
        checkpoint_services._checkpoint_directory(tmp_path / "missing")

    file_destination = tmp_path / "not-a-directory"
    file_destination.write_text("not a directory", encoding="utf-8")
    with pytest.raises(ValidationError, match="not a directory"):
        checkpoint_services._checkpoint_directory(file_destination)

    output_path = tmp_path / "checkpoint.json"
    with (
        patch("audit.checkpoints.os.fdopen", side_effect=OSError("write setup failed")),
        pytest.raises(OSError, match="write setup failed"),
    ):
        checkpoint_services._write_external_document(output_path, {"checkpoint": {}})
    assert list(tmp_path.glob(".*.tmp")) == []


@pytest.mark.django_db
def test_checkpoint_rejects_weak_keys_and_unsafe_key_identifiers(
    checkpoint_household,
    tmp_path: Path,
) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValidationError, match="too short"):
        write_household_checkpoint(
            household=checkpoint_household,
            directory=tmp_path,
            signing_key=b"short",
            signing_key_id="test-key-v1",
        )
    with pytest.raises(ValidationError, match="ID is invalid"):
        write_household_checkpoint(
            household=checkpoint_household,
            directory=tmp_path,
            signing_key=SIGNING_KEY,
            signing_key_id="../unsafe-key",
        )
    assert AuditCheckpoint.objects.count() == 0
