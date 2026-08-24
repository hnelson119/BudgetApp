from typing import ClassVar

from django import forms

from notifications.models import NotificationPreference


class NotificationPreferenceForm(forms.ModelForm):
    class Meta:
        model = NotificationPreference
        fields = (
            "due_alerts",
            "upcoming_due_days",
            "missing_income_alerts",
            "missing_income_grace_days",
            "deficit_alerts",
            "goal_alerts",
            "backup_alerts",
            "login_alerts",
            "integrity_alerts",
        )
        labels: ClassVar[dict[str, str]] = {
            "due_alerts": "Upcoming and overdue bills",
            "upcoming_due_days": "Upcoming bill notice (days)",
            "missing_income_alerts": "Expected paychecks not received",
            "missing_income_grace_days": "Missing paycheck grace period (days)",
            "deficit_alerts": "Projected paycheck-period deficits",
            "goal_alerts": "Goal milestones",
            "backup_alerts": "Missing or overdue backups",
            "login_alerts": "New sessions and repeated login failures",
            "integrity_alerts": "Audit integrity and checkpoint problems",
        }
        help_texts: ClassVar[dict[str, str]] = {
            "upcoming_due_days": "Choose 0 for same-day notices or up to 30 days.",
            "missing_income_grace_days": "Wait this many days before flagging expected income.",
        }
        widgets: ClassVar[dict[str, forms.Widget]] = {
            "upcoming_due_days": forms.NumberInput(attrs={"min": 0, "max": 30}),
            "missing_income_grace_days": forms.NumberInput(attrs={"min": 0, "max": 30}),
        }


class NotificationHistoryFilterForm(forms.Form):
    status = forms.ChoiceField(
        required=False,
        choices=(("active", "Active"), ("all", "All history")),
        initial="active",
        widget=forms.RadioSelect,
    )
