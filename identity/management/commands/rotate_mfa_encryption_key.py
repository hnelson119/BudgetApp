from __future__ import annotations

from typing import Any

from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.core.management.base import BaseCommand, CommandError, CommandParser

from config.settings.environment import required_secret_file
from identity.services.mfa import rotate_mfa_encryption_key


class Command(BaseCommand):
    help = "Transactionally rotate every stored MFA seed to a staged file-mounted key."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--new-version", required=True, type=int)
        parser.add_argument("--reason", required=True)
        parser.add_argument("--confirm", required=True)

    def handle(self, *args: Any, **options: Any) -> None:
        new_version = int(options["new_version"])
        if options["confirm"] != f"rotate-to-v{new_version}":
            raise CommandError("Confirmation did not match; nothing was changed.")
        try:
            new_key = required_secret_file(
                "DJANGO_MFA_ENCRYPTION_KEY_NEXT",
                minimum_length=43,
            )
            result = rotate_mfa_encryption_key(
                new_encryption_key=new_key,
                new_key_version=new_version,
                reason=str(options["reason"]),
            )
        except (ImproperlyConfigured, ValidationError) as error:
            raise CommandError(str(error)) from error

        self.stdout.write(
            self.style.SUCCESS(
                "MFA encryption key rotation completed atomically: "
                f"version {result.previous_key_version} to {result.new_key_version}; "
                f"{result.credential_count} credential(s), "
                f"{result.household_count} protected audit event(s)."
            )
        )
