from __future__ import annotations

import uuid
from typing import Any, cast

from django import forms
from django.core.exceptions import ValidationError
from django.db.models import Q

from households.models import Category, Household
from imports.models import ImportBatch
from ledger.models import FinancialAccount


class CSVUploadForm(forms.Form):
    target_account = forms.ModelChoiceField(
        queryset=FinancialAccount.objects.none(),
        label="Account",
        help_text="Every imported expense will be recorded against this account.",
    )
    csv_file = forms.FileField(
        label="CSV file",
        help_text="UTF-8 CSV only; maximum 5 MiB and 10,000 transaction rows.",
        widget=forms.ClearableFileInput(attrs={"accept": ".csv,text/csv"}),
    )
    submission_token = forms.UUIDField(widget=forms.HiddenInput)

    def __init__(self, *args: Any, household: Household, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        cast(
            forms.ModelChoiceField, self.fields["target_account"]
        ).queryset = FinancialAccount.objects.filter(
            household=household,
            archived_at__isnull=True,
        ).filter(
            Q(classification=FinancialAccount.Classification.ASSET)
            | Q(
                account_type=FinancialAccount.AccountType.CREDIT_CARD,
                classification=FinancialAccount.Classification.LIABILITY,
            )
        )
        if not self.is_bound:
            self.initial.setdefault("submission_token", uuid.uuid4())


def _guess_header(headers: tuple[str, ...], candidates: tuple[str, ...]) -> str:
    normalized = {header.casefold().replace("_", " "): header for header in headers}
    return next((normalized[value] for value in candidates if value in normalized), "")


class CSVMappingForm(forms.Form):
    date_column = forms.ChoiceField(label="Transaction date column")
    description_column = forms.ChoiceField(label="Description column")
    amount_column = forms.ChoiceField(label="Amount column")
    category_column = forms.ChoiceField(
        required=False,
        label="Category column",
        help_text="Exact matches to your active category names are assigned automatically.",
    )
    date_format = forms.ChoiceField(
        choices=(
            ("auto", "Detect common formats"),
            ("iso", "YYYY-MM-DD"),
            ("us_slash", "MM/DD/YYYY"),
            ("us_dash", "MM-DD-YYYY"),
        ),
        initial="auto",
    )
    expense_sign = forms.ChoiceField(
        choices=(
            ("negative", "Negative amounts are expenses"),
            ("positive", "Positive amounts are expenses"),
            ("absolute", "Every non-zero amount is an expense"),
        ),
        help_text="Rows with the opposite sign are excluded during preview.",
    )
    default_category = forms.ModelChoiceField(
        required=False,
        queryset=Category.objects.none(),
        label="Fallback category",
        help_text="Applied when the CSV category is blank or does not match an active category.",
    )

    def __init__(self, *args: Any, batch: ImportBatch, **kwargs: Any) -> None:
        headers = tuple(str(header) for header in batch.headers)
        mapping = cast(dict[str, str], batch.mapping)
        initial = dict(kwargs.pop("initial", {}))
        if mapping:
            initial.update(mapping)
        else:
            initial.update(
                {
                    "date_column": _guess_header(
                        headers,
                        ("date", "transaction date", "posted date"),
                    ),
                    "description_column": _guess_header(
                        headers,
                        ("description", "memo", "name", "merchant"),
                    ),
                    "amount_column": _guess_header(
                        headers,
                        ("amount", "transaction amount", "debit"),
                    ),
                    "category_column": _guess_header(
                        headers,
                        ("category", "category name"),
                    ),
                    "expense_sign": (
                        "positive"
                        if batch.target_account.account_type
                        == FinancialAccount.AccountType.CREDIT_CARD
                        else "negative"
                    ),
                }
            )
        kwargs["initial"] = initial
        super().__init__(*args, **kwargs)
        choices = tuple((header, header) for header in headers)
        cast(forms.ChoiceField, self.fields["date_column"]).choices = choices
        cast(forms.ChoiceField, self.fields["description_column"]).choices = choices
        cast(forms.ChoiceField, self.fields["amount_column"]).choices = choices
        cast(forms.ChoiceField, self.fields["category_column"]).choices = (
            ("", "No category column"),
            *choices,
        )
        cast(
            forms.ModelChoiceField, self.fields["default_category"]
        ).queryset = Category.objects.filter(
            household=batch.household,
            is_archived=False,
        ).order_by("sort_order", "name")

    def clean(self) -> dict[str, Any]:
        cleaned = super().clean() or {}
        selected = tuple(
            str(cleaned.get(name, ""))
            for name in ("date_column", "description_column", "amount_column")
        )
        if all(selected) and len(set(selected)) != len(selected):
            raise ValidationError("Date, description, and amount must use different columns.")
        category_column = str(cleaned.get("category_column", ""))
        if category_column and category_column in selected:
            raise ValidationError("The category must use a different column.")
        return cleaned


class CSVCommitForm(forms.Form):
    confirm = forms.BooleanField(
        label="I reviewed the preview and want to create the ready transactions.",
    )
    confirmation_token = forms.UUIDField(widget=forms.HiddenInput)


class CSVAbandonForm(forms.Form):
    confirm = forms.BooleanField(
        label="Discard this staged import and its uncommitted row data.",
    )
