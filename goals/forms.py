from __future__ import annotations

from datetime import date
from decimal import Decimal
from typing import Any, cast

from django import forms
from django.core.exceptions import ValidationError

from debts.models import DebtAccount
from goals.models import GoalContribution, GoalRevision
from goals.services import GoalSpec
from households.models import Household
from ledger.models import FinancialAccount
from periods.models import PayPeriod


class AccountChoiceField(forms.ModelChoiceField):
    pass


class DebtChoiceField(forms.ModelChoiceField):
    pass


class PeriodChoiceField(forms.ModelChoiceField):
    pass


class GoalForm(forms.Form):
    effective_from = forms.DateField(widget=forms.DateInput(attrs={"type": "date"}))
    name = forms.CharField(max_length=120)
    goal_type = forms.ChoiceField(choices=GoalRevision.GoalType.choices)
    opening_amount = forms.DecimalField(
        min_value=Decimal("0.00"),
        max_digits=18,
        decimal_places=2,
        help_text="Progress already made before adding this goal.",
    )
    target_amount = forms.DecimalField(
        min_value=Decimal("0.01"),
        max_digits=18,
        decimal_places=2,
    )
    target_date = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={"type": "date"}),
    )
    contribution_per_period = forms.DecimalField(
        min_value=Decimal("0.00"),
        max_digits=18,
        decimal_places=2,
        help_text="Planned once per paycheck period; use 0 for no recurring funding.",
    )
    priority = forms.IntegerField(
        min_value=1,
        help_text="Lower numbers receive excess allocations first.",
    )
    status = forms.ChoiceField(choices=GoalRevision.Status.choices)
    automatic_excess_allocation = forms.BooleanField(
        required=False,
        help_text=(
            "Off by default. When enabled, this goal may receive a confirmed priority "
            "allocation from Household Reserve."
        ),
    )
    source_account = AccountChoiceField(queryset=FinancialAccount.objects.none())
    destination_account = AccountChoiceField(
        queryset=FinancialAccount.objects.none(),
        required=False,
        help_text="Required for savings and investing goals.",
    )
    linked_debt = DebtChoiceField(
        queryset=DebtAccount.objects.none(),
        required=False,
        help_text="Required instead of a destination account for debt-payoff goals.",
    )
    notes = forms.CharField(
        required=False,
        max_length=500,
        widget=forms.Textarea(attrs={"rows": 3}),
    )
    reason = forms.CharField(
        required=False,
        max_length=500,
        widget=forms.Textarea(attrs={"rows": 2}),
    )
    preview_fingerprint = forms.CharField(required=False, widget=forms.HiddenInput)

    def __init__(
        self,
        *args: Any,
        household: Household,
        is_revision: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        assets = FinancialAccount.objects.filter(
            household=household,
            classification=FinancialAccount.Classification.ASSET,
            archived_at__isnull=True,
        ).order_by("name")
        cast(AccountChoiceField, self.fields["source_account"]).queryset = assets
        cast(AccountChoiceField, self.fields["destination_account"]).queryset = assets
        cast(DebtChoiceField, self.fields["linked_debt"]).queryset = DebtAccount.objects.filter(
            household=household,
            status=DebtAccount.Status.ACTIVE,
            financial_account__isnull=False,
        ).order_by("name")
        self.is_revision = is_revision
        if is_revision:
            self.fields.pop("opening_amount")
            self.fields["reason"].required = True
            self.fields["reason"].help_text = "Stored in the protected audit history."
        else:
            self.fields.pop("reason")

    def clean(self) -> dict[str, object]:
        cleaned = super().clean() or {}
        goal_type = cleaned.get("goal_type")
        destination = cleaned.get("destination_account")
        linked_debt = cleaned.get("linked_debt")
        if goal_type == GoalRevision.GoalType.DEBT_PAYOFF:
            if linked_debt is None:
                self.add_error("linked_debt", "Choose the debt this goal will pay down.")
            if destination is not None:
                self.add_error(
                    "destination_account",
                    "Debt-payoff goals use the linked debt instead of a destination account.",
                )
        else:
            if destination is None:
                self.add_error("destination_account", "Choose the account that receives funding.")
            if linked_debt is not None:
                self.add_error("linked_debt", "Only debt-payoff goals may link a debt.")
        source = cleaned.get("source_account")
        if source is not None and destination is not None and source == destination:
            self.add_error("destination_account", "Source and destination accounts must differ.")
        target_date = cleaned.get("target_date")
        effective_from = cleaned.get("effective_from")
        if (
            isinstance(target_date, date)
            and isinstance(effective_from, date)
            and target_date < effective_from
        ):
            self.add_error("target_date", "Target date cannot precede the effective date.")
        return cleaned

    def goal_spec(self) -> GoalSpec:
        if not self.is_valid():
            raise ValidationError("Correct the goal form before building a preview.")
        return GoalSpec(
            effective_from=cast(date, self.cleaned_data["effective_from"]),
            name=str(self.cleaned_data["name"]),
            goal_type=str(self.cleaned_data["goal_type"]),
            target_amount=cast(Decimal, self.cleaned_data["target_amount"]),
            target_date=cast(date | None, self.cleaned_data.get("target_date")),
            contribution_per_period=cast(
                Decimal,
                self.cleaned_data["contribution_per_period"],
            ),
            priority=int(self.cleaned_data["priority"]),
            status=str(self.cleaned_data["status"]),
            automatic_excess_allocation=bool(self.cleaned_data["automatic_excess_allocation"]),
            source_account=cast(FinancialAccount, self.cleaned_data["source_account"]),
            destination_account=cast(
                FinancialAccount | None,
                self.cleaned_data.get("destination_account"),
            ),
            linked_debt=cast(DebtAccount | None, self.cleaned_data.get("linked_debt")),
            notes=str(self.cleaned_data["notes"]),
        )


class GoalContributionForm(forms.Form):
    pay_period = PeriodChoiceField(queryset=PayPeriod.objects.none())
    amount = forms.DecimalField(min_value=Decimal("0.01"), max_digits=18, decimal_places=2)
    effective_date = forms.DateField(widget=forms.DateInput(attrs={"type": "date"}))
    reason = forms.CharField(required=False, max_length=500)

    def __init__(
        self,
        *args: Any,
        household: Household,
        occurrence_period: PayPeriod | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        periods = PayPeriod.objects.filter(household=household).exclude(
            status=PayPeriod.Status.CLOSED
        )
        if occurrence_period is not None:
            periods = periods.filter(pk=occurrence_period.pk)
            self.fields["pay_period"].disabled = True
        cast(PeriodChoiceField, self.fields["pay_period"]).queryset = periods.order_by(
            "-start_date"
        )


class ReserveAllocationForm(forms.Form):
    amount = forms.DecimalField(min_value=Decimal("0.01"), max_digits=18, decimal_places=2)
    reason = forms.CharField(
        max_length=500,
        widget=forms.Textarea(attrs={"rows": 2}),
        help_text="Required for the protected reserve and goal audit trail.",
    )
    preview_fingerprint = forms.CharField(required=False, widget=forms.HiddenInput)


class PriorityAllocationForm(forms.Form):
    amount = forms.DecimalField(
        required=False,
        min_value=Decimal("0.01"),
        max_digits=18,
        decimal_places=2,
        help_text="Leave blank to allocate all available reserve across eligible goals.",
    )
    reason = forms.CharField(
        max_length=500,
        widget=forms.Textarea(attrs={"rows": 2}),
    )
    preview_fingerprint = forms.CharField(required=False, widget=forms.HiddenInput)


class GoalStatusForm(forms.Form):
    effective_from = forms.DateField(widget=forms.DateInput(attrs={"type": "date"}))
    status = forms.ChoiceField(choices=GoalRevision.Status.choices)
    reason = forms.CharField(max_length=500, widget=forms.Textarea(attrs={"rows": 2}))


def contribution_type_for_occurrence(occurrence_present: bool) -> str:
    if occurrence_present:
        return GoalContribution.ContributionType.SCHEDULED
    return GoalContribution.ContributionType.MANUAL
