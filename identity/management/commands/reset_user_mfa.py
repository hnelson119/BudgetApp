from __future__ import annotations

import uuid
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import transaction

from audit.services import append_event
from households.models import HouseholdMembership
from identity.models import User
from identity.services.mfa import reset_mfa


class Command(BaseCommand):
    help = "Emergency-reset one user's MFA and sessions from the trusted host console."

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
        confirmation = input(f"Type {user.email} to confirm the emergency MFA reset: ").strip()
        if confirmation.casefold() != user.email.casefold():
            raise CommandError("Confirmation did not match; nothing was changed.")

        memberships = list(
            HouseholdMembership.objects.filter(user=user, is_active=True).select_related(
                "household"
            )
        )
        if not memberships:
            raise CommandError("The account has no active household membership.")

        with transaction.atomic():
            previous_version = user.session_version
            new_version = reset_mfa(user)
            for membership in memberships:
                append_event(
                    household=membership.household,
                    actor=None,
                    action="auth.mfa_emergency_reset",
                    entity_type="identity.user",
                    entity_id=user.pk,
                    request_id=f"recovery-{uuid.uuid4().hex}",
                    before={"mfa_enrolled": True, "session_version": previous_version},
                    after={"mfa_enrolled": False, "session_version": new_version},
                    reason=reason,
                )

        self.stdout.write(
            self.style.WARNING("MFA and recovery codes reset; all existing sessions are revoked.")
        )
