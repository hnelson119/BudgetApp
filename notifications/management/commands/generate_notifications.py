from __future__ import annotations

import os
from datetime import date
from pathlib import Path
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from households.models import Household
from notifications.services import refresh_household_notifications


class Command(BaseCommand):
    help = "Generate and resolve in-app household notifications from authoritative records."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--household-id")
        parser.add_argument("--today")
        parser.add_argument(
            "--backup-max-age-hours",
            type=int,
            default=int(os.getenv("BUDGET_BACKUP_MAX_AGE_HOURS", "36")),
        )

    def handle(self, *args: Any, **options: Any) -> None:
        households = Household.objects.order_by("pk")
        if options.get("household_id"):
            households = households.filter(pk=options["household_id"])
        try:
            supplied_today = date.fromisoformat(options["today"]) if options.get("today") else None
        except ValueError as error:
            raise CommandError("--today must use YYYY-MM-DD format.") from error
        status_name = os.getenv("BUDGET_BACKUP_STATUS_FILE", "").strip()
        status_path = Path(status_name) if status_name else None
        total_created = 0
        total_resolved = 0
        for household in households:
            try:
                result = refresh_household_notifications(
                    household=household,
                    today=supplied_today,
                    backup_status_path=status_path,
                    backup_max_age_hours=options["backup_max_age_hours"],
                )
            except Exception as error:
                raise CommandError(
                    f"Notification generation failed for household {household.pk}."
                ) from error
            total_created += result.created
            total_resolved += result.resolved
        self.stdout.write(
            self.style.SUCCESS(
                f"Notification generation complete: {total_created} created, "
                f"{total_resolved} resolved."
            )
        )
