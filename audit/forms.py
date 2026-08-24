from __future__ import annotations

from typing import Any, cast

from django import forms

from audit.models import AuditEvent
from core.forms import html_date_input
from households.models import Household
from identity.models import User


class AuditFilterForm(forms.Form):
    q = forms.CharField(
        required=False,
        max_length=120,
        label="Search",
        widget=forms.SearchInput(attrs={"placeholder": "Action, record, reason, or person"}),
    )
    action = forms.ChoiceField(required=False, choices=(), label="Action")
    entity_type = forms.ChoiceField(required=False, choices=(), label="Record type")
    actor = forms.ChoiceField(required=False, choices=(), label="Person")
    date_from = forms.DateField(
        required=False,
        label="From",
        widget=html_date_input(),
    )
    date_to = forms.DateField(
        required=False,
        label="Through",
        widget=html_date_input(),
    )

    def __init__(self, *args: Any, household: Household, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        events = AuditEvent.objects.filter(household=household)
        actions = events.order_by("action").values_list("action", flat=True).distinct()
        entity_types = (
            events.order_by("entity_type").values_list("entity_type", flat=True).distinct()
        )
        actor_ids = events.exclude(actor_id__isnull=True).values_list("actor_id", flat=True)
        actors = User.objects.filter(pk__in=actor_ids).order_by("display_name", "email")
        cast(forms.ChoiceField, self.fields["action"]).choices = [
            ("", "All actions"),
            *((item, item) for item in actions),
        ]
        cast(forms.ChoiceField, self.fields["entity_type"]).choices = [
            ("", "All record types"),
            *((item, item) for item in entity_types),
        ]
        cast(forms.ChoiceField, self.fields["actor"]).choices = [
            ("", "Everyone"),
            ("system", "System"),
            *((str(actor.pk), actor.display_name or actor.email) for actor in actors),
        ]

    def clean(self) -> dict[str, Any]:
        cleaned = super().clean() or {}
        date_from = cleaned.get("date_from")
        date_to = cleaned.get("date_to")
        if date_from and date_to and date_to < date_from:
            raise forms.ValidationError("The ending audit date cannot be before the starting date.")
        return cleaned
