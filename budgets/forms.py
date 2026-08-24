from __future__ import annotations

from decimal import Decimal
from typing import Any, cast

from django import forms
from django.core.exceptions import ValidationError
from django.db.models import Q

from households.models import Category, Household
from ledger.models import JournalEntry
from periods.models import PayPeriod
from schedules.models import Occurrence, RecurringSource
from schedules.recurrence import BusinessDayAdjustment, Frequency, RecurrenceRule
from schedules.services import RevisionSpec

WEEKDAY_CHOICES = (
    (0, "Monday"),
    (1, "Tuesday"),
    (2, "Wednesday"),
    (3, "Thursday"),
    (4, "Friday"),
    (5, "Saturday"),
    (6, "Sunday"),
)


class HouseholdForm(forms.Form):
    household: Household

    def __init__(self, *args: Any, household: Household, **kwargs: Any) -> None:
        self.household = household
        super().__init__(*args, **kwargs)


class VariableBudgetForm(HouseholdForm):
    category = forms.ModelChoiceField(queryset=Category.objects.none())
    planned_amount = forms.DecimalField(min_value=Decimal("0.00"), max_digits=18, decimal_places=2)
    notes = forms.CharField(
        required=False, max_length=500, widget=forms.Textarea(attrs={"rows": 3})
    )

    def __init__(self, *args: Any, household: Household, **kwargs: Any) -> None:
        super().__init__(*args, household=household, **kwargs)
        cast(forms.ModelChoiceField, self.fields["category"]).queryset = Category.objects.filter(
            household=household,
            is_archived=False,
        )


class CategoryForm(forms.Form):
    name = forms.CharField(max_length=80)
    color = forms.RegexField(regex=r"^#[0-9A-Fa-f]{6}$", initial="#49D6A6")
    sort_order = forms.IntegerField(min_value=0, initial=0)


class OccurrenceOverrideForm(forms.Form):
    planned_amount = forms.DecimalField(min_value=Decimal("0.00"), max_digits=18, decimal_places=2)
    expected_date = forms.DateField(widget=forms.DateInput(attrs={"type": "date"}))
    reason = forms.CharField(max_length=500, widget=forms.Textarea(attrs={"rows": 3}))


class OccurrenceMoveForm(HouseholdForm):
    target_period = forms.ModelChoiceField(queryset=PayPeriod.objects.none())
    reason = forms.CharField(max_length=500, widget=forms.Textarea(attrs={"rows": 3}))

    def __init__(
        self,
        *args: Any,
        household: Household,
        occurrence: Occurrence,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, household=household, **kwargs)
        target_periods = PayPeriod.objects.filter(household=household)
        if occurrence.pay_period_id is not None:
            target_periods = target_periods.exclude(pk=occurrence.pay_period_id)
        cast(
            forms.ModelChoiceField, self.fields["target_period"]
        ).queryset = target_periods.exclude(status=PayPeriod.Status.CLOSED).order_by("start_date")


class OccurrenceCancelForm(forms.Form):
    scope = forms.ChoiceField(
        choices=(("one", "Only this occurrence"), ("future", "This and all future occurrences"))
    )
    reason = forms.CharField(max_length=500, widget=forms.Textarea(attrs={"rows": 3}))
    confirm = forms.BooleanField(label="I understand this changes the budget schedule.")


class ReconciliationForm(HouseholdForm):
    journal_entry = forms.ModelChoiceField(queryset=JournalEntry.objects.none())
    amount = forms.DecimalField(min_value=Decimal("0.01"), max_digits=18, decimal_places=2)

    def __init__(
        self,
        *args: Any,
        household: Household,
        occurrence: Occurrence,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, household=household, **kwargs)
        compatible = {
            "income": (JournalEntry.EntryType.INCOME,),
            "fixed_expense": (JournalEntry.EntryType.EXPENSE, JournalEntry.EntryType.INTEREST_FEE),
            "debt_payment": (JournalEntry.EntryType.DEBT_PAYMENT,),
            "goal_contribution": (JournalEntry.EntryType.GOAL_CONTRIBUTION,),
        }[occurrence.source.kind]
        entries = JournalEntry.objects.filter(
            household=household,
            entry_type__in=compatible,
            reversal_of__isnull=True,
        )
        if occurrence.source.kind == RecurringSource.Kind.DEBT_PAYMENT:
            entries = entries.filter(
                Q(card_payment_reserve_entry__isnull=True)
                | Q(card_payment_reserve_entry__debt_payoff__gt=0)
            )
        cast(forms.ModelChoiceField, self.fields["journal_entry"]).queryset = entries.order_by(
            "-effective_at"
        )


class ReserveAllocationForm(forms.Form):
    amount = forms.DecimalField(min_value=Decimal("0.01"), max_digits=18, decimal_places=2)
    allocation_label = forms.CharField(label="Destination", max_length=120)
    reason = forms.CharField(
        required=False, max_length=500, widget=forms.Textarea(attrs={"rows": 3})
    )


class FixedExpenseScheduleForm(HouseholdForm):
    name = forms.CharField(max_length=120)
    category = forms.ModelChoiceField(queryset=Category.objects.none())
    expected_amount = forms.DecimalField(
        label="Expected amount",
        min_value=Decimal("0.00"),
        max_digits=18,
        decimal_places=2,
    )
    frequency = forms.ChoiceField(
        choices=(
            (Frequency.ONCE.value, "One time"),
            (Frequency.DAILY.value, "Every N days"),
            (Frequency.WEEKLY.value, "Weekly / every N weeks"),
            (Frequency.MONTHLY_DAY.value, "Fixed day every N months"),
            (Frequency.MONTHLY_NTH_WEEKDAY.value, "Nth weekday every N months"),
            (Frequency.MONTHLY_LAST_WEEKDAY.value, "Last weekday every N months"),
            (Frequency.ANNUAL.value, "Annual date"),
        )
    )
    interval = forms.IntegerField(min_value=1, max_value=366, initial=1)
    start_date = forms.DateField(widget=forms.DateInput(attrs={"type": "date"}))
    end_date = forms.DateField(required=False, widget=forms.DateInput(attrs={"type": "date"}))
    weekdays = forms.MultipleChoiceField(
        required=False,
        choices=WEEKDAY_CHOICES,
        widget=forms.CheckboxSelectMultiple,
        help_text="Used for weekly schedules; choose one or more days.",
    )
    day_of_month = forms.IntegerField(required=False, min_value=1, max_value=31)
    weekday = forms.ChoiceField(
        required=False, choices=(("", "Choose a weekday"), *WEEKDAY_CHOICES)
    )
    ordinal = forms.IntegerField(required=False, min_value=1, max_value=5)
    month_of_year = forms.IntegerField(required=False, min_value=1, max_value=12)
    adjustment_policy = forms.ChoiceField(
        label="Weekend/holiday adjustment",
        choices=(
            (BusinessDayAdjustment.NONE.value, "No adjustment"),
            (BusinessDayAdjustment.PREVIOUS.value, "Previous business day"),
            (BusinessDayAdjustment.NEXT.value, "Next business day"),
        ),
        initial=BusinessDayAdjustment.PREVIOUS.value,
    )
    is_required = forms.BooleanField(required=False, initial=True)
    notes = forms.CharField(
        required=False, max_length=500, widget=forms.Textarea(attrs={"rows": 3})
    )
    preview_fingerprint = forms.CharField(required=False, widget=forms.HiddenInput)

    def __init__(self, *args: Any, household: Household, **kwargs: Any) -> None:
        super().__init__(*args, household=household, **kwargs)
        cast(forms.ModelChoiceField, self.fields["category"]).queryset = Category.objects.filter(
            household=household,
            is_archived=False,
        )

    def revision_spec(self) -> RevisionSpec:
        if not self.is_valid():
            raise ValidationError("Correct the schedule before previewing it.")
        cleaned = self.cleaned_data
        frequency = Frequency(str(cleaned["frequency"]))
        rule = RecurrenceRule(
            frequency=frequency,
            start_date=cleaned["start_date"],
            end_date=cleaned.get("end_date"),
            interval=cleaned["interval"],
            weekdays=tuple(int(value) for value in cleaned.get("weekdays", ())),
            day_of_month=cleaned.get("day_of_month"),
            weekday=int(cleaned["weekday"]) if cleaned.get("weekday") != "" else None,
            ordinal=cleaned.get("ordinal"),
            month_of_year=cleaned.get("month_of_year"),
        )
        rule.validate()
        return RevisionSpec(
            effective_from=cleaned["start_date"],
            expected_amount=cleaned["expected_amount"],
            rule=rule,
            adjustment_policy=BusinessDayAdjustment(str(cleaned["adjustment_policy"])),
        )

    def clean(self) -> dict[str, Any]:
        cleaned = super().clean() or {}
        if self.errors:
            return cleaned
        try:
            frequency = Frequency(str(cleaned["frequency"]))
            RecurrenceRule(
                frequency=frequency,
                start_date=cleaned["start_date"],
                end_date=cleaned.get("end_date"),
                interval=cleaned["interval"],
                weekdays=tuple(int(value) for value in cleaned.get("weekdays", ())),
                day_of_month=cleaned.get("day_of_month"),
                weekday=int(cleaned["weekday"]) if cleaned.get("weekday") != "" else None,
                ordinal=cleaned.get("ordinal"),
                month_of_year=cleaned.get("month_of_year"),
            ).validate()
        except (KeyError, TypeError, ValueError, ValidationError) as error:
            raise ValidationError(str(error)) from error
        return cleaned
