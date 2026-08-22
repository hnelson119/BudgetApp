from __future__ import annotations

import getpass
import uuid
from typing import Any

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import transaction

from audit.services import append_event
from households.models import Household, HouseholdMembership
from identity.models import User


class Command(BaseCommand):
    help = "Create the one household and its two distinct users without command-line passwords."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--household-name", required=True)
        parser.add_argument("--user-email", action="append", dest="user_emails", required=True)
        parser.add_argument("--display-name", action="append", dest="display_names", required=True)

    def _read_password(self, *, email: str) -> str:
        password = getpass.getpass(f"Password for {email}: ")
        confirmation = getpass.getpass(f"Confirm password for {email}: ")
        if not password or password != confirmation:
            raise CommandError("Passwords were empty or did not match.")
        candidate = User(email=email)
        try:
            validate_password(password, candidate)
        except ValidationError as error:
            raise CommandError("Password validation failed: " + " ".join(error.messages)) from error
        return password

    def handle(self, *args: Any, **options: Any) -> None:
        household_name = str(options["household_name"]).strip()
        emails = [str(value).strip().casefold() for value in options["user_emails"]]
        display_names = [str(value).strip() for value in options["display_names"]]
        if not household_name:
            raise CommandError("The household name cannot be empty.")
        if len(emails) != 2 or len(display_names) != 2:
            raise CommandError("Provide exactly two --user-email and two --display-name values.")
        if any(not value for value in (*emails, *display_names)) or len(set(emails)) != 2:
            raise CommandError("Both users need distinct, non-empty email addresses and names.")
        if Household.objects.exists() or User.objects.exists():
            raise CommandError("Bootstrap is allowed only on an empty application database.")

        passwords = [self._read_password(email=email) for email in emails]
        if passwords[0] == passwords[1]:
            raise CommandError("The two accounts must not share a password.")

        with transaction.atomic():
            household = Household.objects.create(name=household_name)
            for email, display_name, password in zip(
                emails,
                display_names,
                passwords,
                strict=True,
            ):
                user = User.objects.create_user(
                    email=email,
                    display_name=display_name,
                    password=password,
                )
                HouseholdMembership.objects.create(household=household, user=user)
            append_event(
                household=household,
                actor=None,
                action="household.bootstrap_completed",
                entity_type="household",
                entity_id=household.pk,
                request_id=f"bootstrap-{uuid.uuid4().hex}",
                after={"member_count": 2, "mfa_enrollment_required": True},
            )

        for index in range(len(passwords)):
            passwords[index] = ""
        self.stdout.write(
            self.style.SUCCESS(
                "Household and two distinct accounts created. Each user must enroll MFA at login."
            )
        )
