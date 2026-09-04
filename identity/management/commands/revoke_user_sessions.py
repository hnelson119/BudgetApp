from __future__ import annotations

import logging
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from identity.models import User
from identity.services.sessions import (
    administratively_revoke_all_sessions,
    administratively_revoke_user_sessions,
)

security_logger = logging.getLogger("security")


class Command(BaseCommand):
    help = "Administratively revoke application sessions for one account or every account."

    def add_arguments(self, parser: CommandParser) -> None:
        target = parser.add_mutually_exclusive_group(required=True)
        target.add_argument("--email")
        target.add_argument("--all-users", action="store_true")
        parser.add_argument("--reason", required=True)
        parser.add_argument("--confirm", required=True)

    def handle(self, *args: Any, **options: Any) -> None:
        reason = str(options["reason"]).strip()
        if not reason or len(reason) > 500:
            raise CommandError("A reason of 1 to 500 characters is required.")

        if options["all_users"]:
            if options["confirm"] != "revoke-all-sessions":
                raise CommandError("Confirmation did not match; nothing was changed.")
            result = administratively_revoke_all_sessions(reason=reason)
            scope = "all"
        else:
            email = str(options["email"]).strip().casefold()
            user = User.objects.filter(email__iexact=email).first()
            if user is None:
                raise CommandError("No account matched that email address.")
            if str(options["confirm"]).strip().casefold() != user.email.casefold():
                raise CommandError("Confirmation did not match; nothing was changed.")
            result = administratively_revoke_user_sessions(user, reason=reason)
            scope = "individual"

        security_logger.warning(
            "Administrator revoked application sessions.",
            extra={"event": "auth.sessions_administrator_revoked", "result": scope},
        )
        self.stdout.write(
            self.style.WARNING(
                "Administrative session revocation completed for "
                f"{result.affected_users} account(s); "
                f"{result.deleted_sessions} stored session(s) removed."
            )
        )
