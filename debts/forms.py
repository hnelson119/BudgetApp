from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Any, cast
from zoneinfo import ZoneInfo

from django import forms
from django.core.exceptions import ValidationError
from django.db.models import Q
from django.utils import timezone

from debts.models import DebtAccount, DebtTermsRevision
from debts.services.accounts import DebtStatementSpec, DebtTermsSpec
from households.models import Household
from ledger.models import FinancialAccount


class LiabilityChoiceField(forms.ModelChoiceField):
    def label_from_instance(self, obj: FinancialAccount) -> str:
        suffix = f" •••• {obj.last_four}" if obj.last_four else ""
        return f"{obj.name}{suffix}"


class HouseholdForm(forms.Form):
    household: Household

    def __init__(self, *args: Any, household: Household, **kwargs: Any) -> None:
        self.household = household
        super().__init__(*args, **kwargs)


class DebtIdentityFields(HouseholdForm):
    name = forms.CharField(max_length=120)
    debt_type = forms.ChoiceField(choices=DebtAccount.DebtType.choices)
    financial_account = LiabilityChoiceField(
        required=False,
        queryset=FinancialAccount.objects.none(),
        empty_label="No linked ledger account",
        help_text="Optional. Only a nickname and optional last four digits are stored.",
    )
    notes = forms.CharField(
        required=False, max_length=500, widget=forms.Textarea(attrs={"rows": 3})
    )

    def __init__(
        self,
        *args: Any,
        household: Household,
        debt: DebtAccount | None = None,
        **kwargs: Any,
    ) -> None:
        self.debt = debt
        super().__init__(*args, household=household, **kwargs)
        accounts = FinancialAccount.objects.filter(
            household=household,
            archived_at__isnull=True,
            classification=FinancialAccount.Classification.LIABILITY,
        )
        if debt is None:
            accounts = accounts.filter(debt_account__isnull=True)
        else:
            accounts = accounts.filter(Q(debt_account__isnull=True) | Q(debt_account=debt))
        cast(LiabilityChoiceField, self.fields["financial_account"]).queryset = accounts.order_by(
            "name"
        )


class DebtAccountCreateForm(DebtIdentityFields):
    opening_balance = forms.DecimalField(
        min_value=Decimal("0.00"),
        max_digits=18,
        decimal_places=2,
    )
    effective_from = forms.DateField(
        label="Terms effective from",
        widget=forms.DateInput(attrs={"type": "date"}),
    )
    annual_percentage_rate = forms.DecimalField(
        label="APR (%)",
        min_value=Decimal("0"),
        max_value=Decimal("999.9999"),
        max_digits=7,
        decimal_places=4,
    )
    interest_method = forms.ChoiceField(choices=DebtTermsRevision.InterestMethod.choices)
    day_count_basis = forms.ChoiceField(choices=DebtTermsRevision.DayCountBasis.choices)
    minimum_payment = forms.DecimalField(
        min_value=Decimal("0.00"),
        max_digits=18,
        decimal_places=2,
    )
    recurring_extra_payment = forms.DecimalField(
        min_value=Decimal("0.00"),
        max_digits=18,
        decimal_places=2,
        initial=Decimal("0.00"),
    )
    due_day = forms.IntegerField(min_value=1, max_value=31, initial=1)
    custom_priority = forms.IntegerField(
        min_value=1,
        initial=100,
        help_text="Lower numbers are paid first in the custom strategy.",
    )
    projection_notes = forms.CharField(
        required=False,
        max_length=500,
        widget=forms.Textarea(attrs={"rows": 2}),
    )

    field_order = (
        "name",
        "debt_type",
        "financial_account",
        "opening_balance",
        "effective_from",
        "annual_percentage_rate",
        "interest_method",
        "day_count_basis",
        "minimum_payment",
        "recurring_extra_payment",
        "due_day",
        "custom_priority",
        "projection_notes",
        "notes",
    )

    def __init__(self, *args: Any, household: Household, **kwargs: Any) -> None:
        super().__init__(*args, household=household, **kwargs)
        if not self.is_bound:
            today = timezone.localdate(timezone=ZoneInfo(household.time_zone))
            self.initial.setdefault("effective_from", today)

    def terms_spec(self) -> DebtTermsSpec:
        if not self.is_valid():
            raise ValidationError("Correct the debt before saving it.")
        return DebtTermsSpec(
            effective_from=cast(date, self.cleaned_data["effective_from"]),
            annual_percentage_rate=cast(Decimal, self.cleaned_data["annual_percentage_rate"]),
            interest_method=str(self.cleaned_data["interest_method"]),
            day_count_basis=str(self.cleaned_data["day_count_basis"]),
            minimum_payment=cast(Decimal, self.cleaned_data["minimum_payment"]),
            recurring_extra_payment=cast(
                Decimal,
                self.cleaned_data["recurring_extra_payment"],
            ),
            due_day=int(self.cleaned_data["due_day"]),
            custom_priority=int(self.cleaned_data["custom_priority"]),
            projection_notes=str(self.cleaned_data["projection_notes"]),
        )


class DebtMetadataForm(DebtIdentityFields):
    reason = forms.CharField(
        max_length=500,
        widget=forms.Textarea(attrs={"rows": 3}),
        help_text="The reason is retained in protected audit history.",
    )


class DebtTermsForm(HouseholdForm):
    effective_from = forms.DateField(widget=forms.DateInput(attrs={"type": "date"}))
    annual_percentage_rate = forms.DecimalField(
        label="APR (%)",
        min_value=Decimal("0"),
        max_value=Decimal("999.9999"),
        max_digits=7,
        decimal_places=4,
    )
    interest_method = forms.ChoiceField(choices=DebtTermsRevision.InterestMethod.choices)
    day_count_basis = forms.ChoiceField(choices=DebtTermsRevision.DayCountBasis.choices)
    minimum_payment = forms.DecimalField(
        min_value=Decimal("0.00"),
        max_digits=18,
        decimal_places=2,
    )
    recurring_extra_payment = forms.DecimalField(
        min_value=Decimal("0.00"),
        max_digits=18,
        decimal_places=2,
    )
    due_day = forms.IntegerField(min_value=1, max_value=31)
    custom_priority = forms.IntegerField(min_value=1)
    projection_notes = forms.CharField(
        required=False,
        max_length=500,
        widget=forms.Textarea(attrs={"rows": 2}),
    )
    reason = forms.CharField(
        max_length=500,
        widget=forms.Textarea(attrs={"rows": 3}),
        help_text="Creates a new immutable terms revision; prior terms remain unchanged.",
    )

    def terms_spec(self) -> DebtTermsSpec:
        if not self.is_valid():
            raise ValidationError("Correct the debt terms before saving them.")
        return DebtTermsSpec(
            effective_from=cast(date, self.cleaned_data["effective_from"]),
            annual_percentage_rate=cast(Decimal, self.cleaned_data["annual_percentage_rate"]),
            interest_method=str(self.cleaned_data["interest_method"]),
            day_count_basis=str(self.cleaned_data["day_count_basis"]),
            minimum_payment=cast(Decimal, self.cleaned_data["minimum_payment"]),
            recurring_extra_payment=cast(
                Decimal,
                self.cleaned_data["recurring_extra_payment"],
            ),
            due_day=int(self.cleaned_data["due_day"]),
            custom_priority=int(self.cleaned_data["custom_priority"]),
            projection_notes=str(self.cleaned_data["projection_notes"]),
        )


class DebtStatementForm(HouseholdForm):
    statement_date = forms.DateField(widget=forms.DateInput(attrs={"type": "date"}))
    period_start = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={"type": "date"}),
    )
    period_end = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={"type": "date"}),
    )
    due_date = forms.DateField(required=False, widget=forms.DateInput(attrs={"type": "date"}))
    statement_balance = forms.DecimalField(
        min_value=Decimal("0.00"),
        max_digits=18,
        decimal_places=2,
    )
    annual_percentage_rate = forms.DecimalField(
        label="Statement APR (%)",
        min_value=Decimal("0"),
        max_value=Decimal("999.9999"),
        max_digits=7,
        decimal_places=4,
    )
    minimum_payment = forms.DecimalField(
        min_value=Decimal("0.00"),
        max_digits=18,
        decimal_places=2,
    )
    principal_paid = forms.DecimalField(
        min_value=Decimal("0.00"), max_digits=18, decimal_places=2, initial=Decimal("0.00")
    )
    interest_charged = forms.DecimalField(
        min_value=Decimal("0.00"), max_digits=18, decimal_places=2, initial=Decimal("0.00")
    )
    fees_charged = forms.DecimalField(
        min_value=Decimal("0.00"), max_digits=18, decimal_places=2, initial=Decimal("0.00")
    )
    escrow_paid = forms.DecimalField(
        min_value=Decimal("0.00"), max_digits=18, decimal_places=2, initial=Decimal("0.00")
    )
    pmi_paid = forms.DecimalField(
        label="PMI paid",
        min_value=Decimal("0.00"),
        max_digits=18,
        decimal_places=2,
        initial=Decimal("0.00"),
    )
    extra_principal_paid = forms.DecimalField(
        min_value=Decimal("0.00"), max_digits=18, decimal_places=2, initial=Decimal("0.00")
    )
    notes = forms.CharField(
        required=False, max_length=500, widget=forms.Textarea(attrs={"rows": 3})
    )

    def statement_spec(self) -> DebtStatementSpec:
        if not self.is_valid():
            raise ValidationError("Correct the statement before saving it.")
        return DebtStatementSpec(
            statement_date=cast(date, self.cleaned_data["statement_date"]),
            statement_balance=cast(Decimal, self.cleaned_data["statement_balance"]),
            annual_percentage_rate=cast(Decimal, self.cleaned_data["annual_percentage_rate"]),
            minimum_payment=cast(Decimal, self.cleaned_data["minimum_payment"]),
            period_start=cast(date | None, self.cleaned_data["period_start"]),
            period_end=cast(date | None, self.cleaned_data["period_end"]),
            due_date=cast(date | None, self.cleaned_data["due_date"]),
            principal_paid=cast(Decimal, self.cleaned_data["principal_paid"]),
            interest_charged=cast(Decimal, self.cleaned_data["interest_charged"]),
            fees_charged=cast(Decimal, self.cleaned_data["fees_charged"]),
            escrow_paid=cast(Decimal, self.cleaned_data["escrow_paid"]),
            pmi_paid=cast(Decimal, self.cleaned_data["pmi_paid"]),
            extra_principal_paid=cast(Decimal, self.cleaned_data["extra_principal_paid"]),
            notes=str(self.cleaned_data["notes"]),
        )


class DebtStatementCorrectionForm(DebtStatementForm):
    reason = forms.CharField(
        max_length=500,
        widget=forms.Textarea(attrs={"rows": 3}),
        help_text="The correction remains linked to the original protected statement.",
    )
    confirm = forms.BooleanField(
        label="I understand this appends a correction and does not edit the original statement.",
    )


class PayoffScenarioForm(forms.Form):
    monthly_extra = forms.DecimalField(
        label="Monthly strategy extra",
        min_value=Decimal("0.00"),
        max_digits=18,
        decimal_places=2,
        initial=Decimal("0.00"),
    )
    start_date = forms.DateField(widget=forms.DateInput(attrs={"type": "date"}))
    maximum_years = forms.IntegerField(
        min_value=1,
        max_value=100,
        initial=40,
        help_text="Projections stop at this horizon if a payment is too low to pay off a debt.",
    )


class DebtStatusConfirmationForm(forms.Form):
    reason = forms.CharField(max_length=500, widget=forms.Textarea(attrs={"rows": 3}))
    confirm = forms.BooleanField(label="I understand this changes the debt's active status.")
