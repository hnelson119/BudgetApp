from __future__ import annotations

import uuid
from datetime import date, datetime, time
from decimal import Decimal
from typing import Any, cast
from zoneinfo import ZoneInfo

from django import forms
from django.core.exceptions import ValidationError
from django.utils import timezone

from core.forms import html_date_input, html_time_input
from households.models import Category, Household
from ledger.models import FinancialAccount, JournalEntry


class AccountChoiceField(forms.ModelChoiceField):
    def label_from_instance(self, obj: FinancialAccount) -> str:
        suffix = f" •••• {obj.last_four}" if obj.last_four else ""
        return f"{obj.name}{suffix} · {obj.get_account_type_display()}"


class HouseholdForm(forms.Form):
    household: Household

    def __init__(self, *args: Any, household: Household, **kwargs: Any) -> None:
        self.household = household
        super().__init__(*args, **kwargs)


class ManualEntryForm(HouseholdForm):
    description = forms.CharField(
        max_length=200,
        help_text="Use a recognizable payee or income-source name.",
    )
    amount = forms.DecimalField(
        min_value=Decimal("0.01"),
        max_digits=18,
        decimal_places=2,
    )
    effective_date = forms.DateField(
        label="Date",
        widget=html_date_input(),
    )
    effective_time = forms.TimeField(
        label="Time",
        widget=html_time_input(),
        input_formats=("%H:%M",),
        help_text="Recorded in the household timezone.",
    )
    note = forms.CharField(
        required=False,
        max_length=500,
        widget=forms.Textarea(attrs={"rows": 3}),
    )
    submission_token = forms.UUIDField(widget=forms.HiddenInput)

    def __init__(self, *args: Any, household: Household, **kwargs: Any) -> None:
        super().__init__(*args, household=household, **kwargs)
        if not self.is_bound:
            local_now = timezone.localtime(timezone.now(), ZoneInfo(household.time_zone))
            self.initial.setdefault("effective_date", local_now.date())
            self.initial.setdefault(
                "effective_time",
                local_now.time().replace(second=0, microsecond=0),
            )
            self.initial.setdefault("submission_token", uuid.uuid4())

    def effective_at(self) -> datetime:
        if not self.is_valid():
            raise ValidationError("Correct the transaction before saving it.")
        local_date = cast(date, self.cleaned_data["effective_date"])
        local_time = cast(time, self.cleaned_data["effective_time"])
        return datetime.combine(local_date, local_time, tzinfo=ZoneInfo(self.household.time_zone))

    def idempotency_key(self) -> str:
        if not self.is_valid():
            raise ValidationError("Correct the transaction before saving it.")
        token = cast(uuid.UUID, self.cleaned_data["submission_token"])
        return f"manual-{token.hex}"


class ExpenseForm(ManualEntryForm):
    account = AccountChoiceField(
        queryset=FinancialAccount.objects.none(),
        label="Paid from account or card",
    )
    category = forms.ModelChoiceField(queryset=Category.objects.none())
    receipt_reference = forms.CharField(
        required=False,
        max_length=255,
        help_text="Optional receipt number or private file reference; no attachment is uploaded.",
    )

    field_order = (
        "description",
        "amount",
        "account",
        "category",
        "effective_date",
        "effective_time",
        "receipt_reference",
        "note",
        "submission_token",
    )

    def __init__(self, *args: Any, household: Household, **kwargs: Any) -> None:
        super().__init__(*args, household=household, **kwargs)
        cast(AccountChoiceField, self.fields["account"]).queryset = FinancialAccount.objects.filter(
            household=household,
            archived_at__isnull=True,
        ).order_by("name")
        cast(forms.ModelChoiceField, self.fields["category"]).queryset = Category.objects.filter(
            household=household,
            is_archived=False,
        )


class IncomeForm(ManualEntryForm):
    destination = AccountChoiceField(
        queryset=FinancialAccount.objects.none(),
        label="Deposit account",
    )

    field_order = (
        "description",
        "amount",
        "destination",
        "effective_date",
        "effective_time",
        "note",
        "submission_token",
    )

    def __init__(self, *args: Any, household: Household, **kwargs: Any) -> None:
        super().__init__(*args, household=household, **kwargs)
        cast(
            AccountChoiceField, self.fields["destination"]
        ).queryset = FinancialAccount.objects.filter(
            household=household,
            archived_at__isnull=True,
            classification=FinancialAccount.Classification.ASSET,
        ).order_by("name")


class CardPaymentForm(ManualEntryForm):
    source = AccountChoiceField(
        queryset=FinancialAccount.objects.none(),
        label="Pay from",
        help_text="Choose the checking, savings, or cash account funding this payment.",
    )

    field_order = (
        "description",
        "amount",
        "source",
        "effective_date",
        "effective_time",
        "note",
        "submission_token",
    )

    def __init__(self, *args: Any, household: Household, **kwargs: Any) -> None:
        super().__init__(*args, household=household, **kwargs)
        cast(AccountChoiceField, self.fields["source"]).queryset = FinancialAccount.objects.filter(
            household=household,
            archived_at__isnull=True,
            classification=FinancialAccount.Classification.ASSET,
        ).order_by("name")


class FinancialAccountForm(forms.Form):
    class Kind:
        CHECKING = "checking"
        SAVINGS = "savings"
        CASH = "cash"
        CREDIT_CARD = "credit_card"
        OTHER_ASSET = "other_asset"
        OTHER_LIABILITY = "other_liability"

    name = forms.CharField(max_length=120)
    kind = forms.ChoiceField(
        label="Account kind",
        choices=(
            (Kind.CHECKING, "Checking"),
            (Kind.SAVINGS, "Savings"),
            (Kind.CASH, "Cash"),
            (Kind.CREDIT_CARD, "Credit card"),
            (Kind.OTHER_ASSET, "Other asset"),
            (Kind.OTHER_LIABILITY, "Other liability"),
        ),
    )
    last_four = forms.RegexField(
        required=False,
        regex=r"^[0-9]{4}$",
        label="Last four digits",
        help_text="Optional. Never enter a full account or card number.",
    )
    notes = forms.CharField(
        required=False,
        max_length=500,
        widget=forms.Textarea(attrs={"rows": 3}),
    )

    def account_type_and_classification(self) -> tuple[str, str]:
        if not self.is_valid():
            raise ValidationError("Correct the account before saving it.")
        kind = str(self.cleaned_data["kind"])
        if kind == self.Kind.CREDIT_CARD:
            return (
                FinancialAccount.AccountType.CREDIT_CARD,
                FinancialAccount.Classification.LIABILITY,
            )
        if kind == self.Kind.OTHER_LIABILITY:
            return (
                FinancialAccount.AccountType.OTHER,
                FinancialAccount.Classification.LIABILITY,
            )
        if kind == self.Kind.OTHER_ASSET:
            return FinancialAccount.AccountType.OTHER, FinancialAccount.Classification.ASSET
        return kind, FinancialAccount.Classification.ASSET


class ReversalForm(HouseholdForm):
    effective_date = forms.DateField(
        label="Refund/reversal date",
        widget=html_date_input(),
    )
    effective_time = forms.TimeField(
        label="Time",
        widget=html_time_input(),
        input_formats=("%H:%M",),
    )
    reason = forms.CharField(
        max_length=500,
        widget=forms.Textarea(attrs={"rows": 4}),
        help_text="The reason is retained in the protected audit trail.",
    )
    confirm = forms.BooleanField(
        label="I understand this creates a permanent linked reversal of the full transaction.",
    )

    def __init__(self, *args: Any, household: Household, **kwargs: Any) -> None:
        super().__init__(*args, household=household, **kwargs)
        if not self.is_bound:
            local_now = timezone.localtime(timezone.now(), ZoneInfo(household.time_zone))
            self.initial.setdefault("effective_date", local_now.date())
            self.initial.setdefault(
                "effective_time",
                local_now.time().replace(second=0, microsecond=0),
            )

    def effective_at(self) -> datetime:
        if not self.is_valid():
            raise ValidationError("Correct the reversal before saving it.")
        local_date = cast(date, self.cleaned_data["effective_date"])
        local_time = cast(time, self.cleaned_data["effective_time"])
        return datetime.combine(local_date, local_time, tzinfo=ZoneInfo(self.household.time_zone))


class CardPurchaseRefundForm(HouseholdForm):
    amount = forms.DecimalField(min_value=Decimal("0.01"), max_digits=18, decimal_places=2)
    effective_date = forms.DateField(
        label="Refund date",
        widget=html_date_input(),
    )
    effective_time = forms.TimeField(
        label="Time",
        widget=html_time_input(),
        input_formats=("%H:%M",),
    )
    reason = forms.CharField(
        max_length=500,
        widget=forms.Textarea(attrs={"rows": 4}),
        help_text="The reason is retained in the protected audit trail.",
    )
    confirm = forms.BooleanField(
        label="I understand this creates a permanent linked refund entry.",
    )
    submission_token = forms.UUIDField(widget=forms.HiddenInput)

    def __init__(
        self,
        *args: Any,
        household: Household,
        remaining: Decimal,
        **kwargs: Any,
    ) -> None:
        self.remaining = remaining
        super().__init__(*args, household=household, **kwargs)
        self.fields["amount"].help_text = f"Up to ${remaining:,.2f} remains refundable."
        self.fields["amount"].widget.attrs["max"] = str(remaining)
        if not self.is_bound:
            local_now = timezone.localtime(timezone.now(), ZoneInfo(household.time_zone))
            self.initial.setdefault("amount", remaining)
            self.initial.setdefault("effective_date", local_now.date())
            self.initial.setdefault(
                "effective_time",
                local_now.time().replace(second=0, microsecond=0),
            )
            self.initial.setdefault("submission_token", uuid.uuid4())

    def clean_amount(self) -> Decimal:
        amount = cast(Decimal, self.cleaned_data["amount"])
        if amount > self.remaining:
            raise ValidationError("The refund cannot exceed the remaining purchase amount.")
        return amount

    def effective_at(self) -> datetime:
        if not self.is_valid():
            raise ValidationError("Correct the refund before saving it.")
        local_date = cast(date, self.cleaned_data["effective_date"])
        local_time = cast(time, self.cleaned_data["effective_time"])
        return datetime.combine(local_date, local_time, tzinfo=ZoneInfo(self.household.time_zone))

    def idempotency_key(self) -> str:
        if not self.is_valid():
            raise ValidationError("Correct the refund before saving it.")
        token = cast(uuid.UUID, self.cleaned_data["submission_token"])
        return f"manual-refund-{token.hex}"


class TransactionFilterForm(forms.Form):
    q = forms.CharField(required=False, max_length=120, label="Search")
    entry_type = forms.ChoiceField(
        required=False,
        label="Type",
        choices=(("", "All types"), *JournalEntry.EntryType.choices),
    )
    account = AccountChoiceField(
        required=False,
        queryset=FinancialAccount.objects.none(),
        empty_label="All accounts",
    )

    def __init__(self, *args: Any, household: Household, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        cast(AccountChoiceField, self.fields["account"]).queryset = FinancialAccount.objects.filter(
            household=household,
        ).order_by("archived_at", "name")
