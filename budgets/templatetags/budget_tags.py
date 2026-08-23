from __future__ import annotations

from datetime import date
from decimal import Decimal, InvalidOperation

from django import template

from schedules.models import Occurrence, RecurringSource

register = template.Library()


@register.filter
def money(value: object) -> str:
    try:
        amount = Decimal(str(value or 0)).quantize(Decimal("0.01"))
    except (InvalidOperation, TypeError, ValueError):
        return "$0.00"
    prefix = "-$" if amount < 0 else "$"
    return f"{prefix}{abs(amount):,.2f}"


@register.filter
def occurrence_status(occurrence: Occurrence, today: date) -> str:
    if occurrence.status == Occurrence.Status.COMPLETED:
        return "Received" if occurrence.source.kind == RecurringSource.Kind.INCOME else "Paid"
    if occurrence.status == Occurrence.Status.CORRECTED:
        return "Corrected"
    if occurrence.status == Occurrence.Status.CANCELLED:
        return "Cancelled"
    if occurrence.status == Occurrence.Status.MOVED:
        return "Moved"
    if occurrence.status == Occurrence.Status.OVERRIDDEN:
        return "Overridden"
    if occurrence.source.kind != RecurringSource.Kind.INCOME and occurrence.expected_date < today:
        return "Overdue"
    return "Upcoming" if occurrence.expected_date >= today else "Scheduled"
