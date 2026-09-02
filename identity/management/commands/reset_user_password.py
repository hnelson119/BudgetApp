from __future__ import annotations

import getpass
import uuid
from typing import Any

from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import transaction

from audit.services import append_event
from households.models import HouseholdMembership
from identity.models import User


class Command(BaseCommand):
    help = "Emergency-reset one user's password and sessions from the trusted host console."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("email")
        parser.add_argument("--reason", required=True)

    def handle(self, *args: Any, **options: Any) -> None:
        email = str(options["email"]).strip().casefold()
        reason = str(options["reason"]).strip()
        if not reason or len(reason) > 500:
            raise CommandError("A reason of 1 to 500 characters is required.")
        user = User.objects.filter(email__iexact=email, is_active=True).first()
        if user is None:
            raise CommandError("No active account matched that email address.")
        memberships = list(
            HouseholdMembership.objects.filter(user=user, is_active=True).select_related(
                "household"
            )
        )
        if not memberships:
            raise CommandError("The account has no active household membership.")

        password = getpass.getpass("New password: ")
        confirmation = getpass.getpass("Confirm new password: ")
        if password != confirmation:
            raise CommandError("Password confirmation did not match; nothing was changed.")
        if user.check_password(password):
            raise CommandError("The replacement password must be different.")
        try:
            validate_password(password, user=user)
        except ValidationError as error:
            raise CommandError("The replacement password did not meet policy.") from error

        with transaction.atomic():
            locked_user = User.objects.select_for_update().get(pk=user.pk)
            previous_version = locked_user.session_version
            locked_user.set_password(password)
            locked_user.session_version += 1
            locked_user.save(update_fields=("password", "session_version"))
            request_id = f"password-recovery-{uuid.uuid4().hex}"
            for membership in memberships:
                append_event(
                    household=membership.household,
                    actor=None,
                    action="auth.password_emergency_reset",
                    entity_type="identity.user",
                    entity_id=locked_user.pk,
                    request_id=request_id,
                    before={"session_version": previous_version},
                    after={
                        "credential_changed": True,
                        "session_version": locked_user.session_version,
                    },
                    reason=reason,
                )

        self.stdout.write(
            self.style.WARNING("Password reset completed; all existing sessions are revoked.")
        )
