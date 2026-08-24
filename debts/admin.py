from django.contrib import admin

from debts.models import DebtAccount, DebtStatement, DebtTermsRevision


class ReadOnlyDebtAdmin(admin.ModelAdmin):
    def has_add_permission(self, request: object) -> bool:
        return False

    def has_change_permission(self, request: object, obj: object | None = None) -> bool:
        return False

    def has_delete_permission(self, request: object, obj: object | None = None) -> bool:
        return False


@admin.register(DebtAccount)
class DebtAccountAdmin(ReadOnlyDebtAdmin):
    list_display = ("name", "household", "debt_type", "current_balance", "status")
    list_filter = ("debt_type", "status")
    search_fields = ("name", "household__name")


@admin.register(DebtTermsRevision)
class DebtTermsRevisionAdmin(ReadOnlyDebtAdmin):
    list_display = (
        "debt",
        "revision_number",
        "effective_from",
        "annual_percentage_rate",
        "minimum_payment",
    )
    list_filter = ("interest_method", "day_count_basis")
    search_fields = ("debt__name", "debt__household__name")


@admin.register(DebtStatement)
class DebtStatementAdmin(ReadOnlyDebtAdmin):
    list_display = (
        "debt",
        "statement_date",
        "statement_balance",
        "annual_percentage_rate",
        "minimum_payment",
    )
    search_fields = ("debt__name", "debt__household__name")
