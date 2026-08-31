from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from audit.checkpoints import verify_checkpoint_document
from audit.models import AuditHead
from audit.services import verify_household_chain
from config.settings.environment import required_environment, required_secret_file
from households.models import Household

_MAX_CHECKPOINT_BYTES = 64 * 1024


class Command(BaseCommand):
    help = "Verify a signed external checkpoint and compare it with the current database head."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("file_name")
        parser.add_argument("--household-id", required=True)

    def handle(self, *args: Any, **options: Any) -> None:
        configured_directory = Path(required_environment("AUDIT_CHECKPOINT_DIRECTORY"))
        try:
            directory = configured_directory.resolve(strict=True)
        except OSError as error:
            raise CommandError("The configured checkpoint directory is unavailable.") from error
        supplied_name = str(options["file_name"])
        if Path(supplied_name).name != supplied_name:
            raise CommandError("Provide a checkpoint filename, not a path.")
        checkpoint_path = directory / supplied_name
        try:
            if (
                not checkpoint_path.is_file()
                or checkpoint_path.stat().st_size > _MAX_CHECKPOINT_BYTES
            ):
                raise CommandError("The checkpoint file is missing or unexpectedly large.")
            document = json.loads(checkpoint_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise CommandError("The checkpoint file could not be parsed safely.") from error

        signing_key = required_secret_file(
            "AUDIT_CHECKPOINT_SIGNING_KEY",
            minimum_length=43,
        ).encode()
        expected_key_id = required_environment("AUDIT_CHECKPOINT_KEY_ID")
        if not isinstance(document, dict) or not verify_checkpoint_document(document, signing_key):
            raise CommandError("The checkpoint signature is invalid.")
        body = document.get("checkpoint")
        signature = document.get("signature")
        if not isinstance(body, dict) or not isinstance(signature, dict):
            raise CommandError("The checkpoint body is invalid.")
        if signature.get("key_id") != expected_key_id:
            raise CommandError("The checkpoint was not signed by the configured key ID.")
        try:
            household_id = uuid.UUID(str(body["household_id"]))
            expected_household_id = uuid.UUID(str(options["household_id"]))
            last_sequence = int(body["last_sequence"])
            event_count = int(body["event_count"])
            chain_head = str(body["chain_head"])
        except (KeyError, TypeError, ValueError) as error:
            raise CommandError("The checkpoint identifiers are invalid.") from error
        if household_id != expected_household_id:
            raise CommandError("The signed checkpoint is for a different household than expected.")
        integrity = verify_household_chain(Household(id=expected_household_id))
        if not integrity.valid:
            raise CommandError("The database audit chain failed integrity verification.")
        head = AuditHead.objects.filter(household_id=household_id).first()
        if (
            head is None
            or head.last_sequence != last_sequence
            or head.event_count != event_count
            or head.chain_head != chain_head
            or integrity.event_count != event_count
            or integrity.chain_head != chain_head
        ):
            raise CommandError("The signed checkpoint does not match the database audit head.")
        self.stdout.write(
            self.style.SUCCESS(
                "Checkpoint signature, complete audit chain, and database head match."
            )
        )
