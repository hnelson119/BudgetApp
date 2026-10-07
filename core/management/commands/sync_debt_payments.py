"""Repair missing debt budget schedules; print counts only, never financial details."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import transaction

from debts.models import DebtAccount
from debts.services.payments import synchronize_debt_payment
from households.models import HouseholdMembership


class Command(BaseCommand):
    help = "Preview or apply idempotent monthly budget schedules for existing active debts."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "--apply", action="store_true", help="Apply the repair; default is preview."
        )

    @transaction.atomic
    def handle(self, *args: Any, **options: Any) -> None:
        debts = list(
            DebtAccount.objects.filter(status=DebtAccount.Status.ACTIVE)
            .select_related("household", "created_by")
            .order_by("household_id", "id")
        )
        if not options["apply"]:
            self.stdout.write(f"Preview: {len(debts)} active debts; no changes made.")
            return
        for debt in debts:
            if (
                not debt.created_by.is_active
                or not HouseholdMembership.objects.filter(
                    household=debt.household, user=debt.created_by, is_active=True
                ).exists()
            ):
                raise CommandError(
                    "Repair requires an active household membership for every debt creator; "
                    "no changes applied."
                )
        request_id = f"debt-payment-repair-{uuid4()}"
        for debt in debts:
            synchronize_debt_payment(debt=debt, actor=debt.created_by, request_id=request_id)
        self.stdout.write(f"Synchronized monthly budget payments for {len(debts)} active debts.")
