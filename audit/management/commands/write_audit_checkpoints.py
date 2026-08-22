from __future__ import annotations

from pathlib import Path
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from audit.checkpoints import write_household_checkpoint
from audit.models import AuditHead
from config.settings.environment import required_environment, required_secret_file
from households.models import Household


class Command(BaseCommand):
    help = "Verify each audit chain and write a signed checkpoint outside the application VM."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--household-id")

    def handle(self, *args: Any, **options: Any) -> None:
        directory = Path(required_environment("AUDIT_CHECKPOINT_DIRECTORY"))
        signing_key = required_secret_file(
            "AUDIT_CHECKPOINT_SIGNING_KEY",
            minimum_length=43,
        ).encode()
        key_id = required_environment("AUDIT_CHECKPOINT_KEY_ID")
        heads = AuditHead.objects.order_by("household_id")
        household_id = options.get("household_id")
        if household_id:
            heads = heads.filter(household_id=household_id)
        if not heads.exists():
            raise CommandError("No matching non-empty household audit chain was found.")

        for head in heads:
            household = Household(id=head.household_id)
            try:
                result = write_household_checkpoint(
                    household=household,
                    directory=directory,
                    signing_key=signing_key,
                    signing_key_id=key_id,
                )
            except Exception as error:
                raise CommandError(
                    f"Audit checkpoint failed for household {head.household_id}."
                ) from error
            self.stdout.write(
                self.style.SUCCESS(f"Wrote protected checkpoint {result.external_path.name}")
            )
