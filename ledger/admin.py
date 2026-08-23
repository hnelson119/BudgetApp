from django.contrib import admin

from .models import BalanceSnapshot, FinancialAccount, JournalEntry, JournalPosting


class ReadOnlyLedgerAdmin(admin.ModelAdmin):
    """Troubleshooting visibility without bypassing audited domain services."""

    def has_add_permission(self, request: object) -> bool:
        return False

    def has_change_permission(self, request: object, obj: object | None = None) -> bool:
        return False

    def has_delete_permission(self, request: object, obj: object | None = None) -> bool:
        return False


@admin.register(FinancialAccount)
class FinancialAccountAdmin(ReadOnlyLedgerAdmin):
    list_display = ("name", "household", "account_type", "classification", "archived_at")
    list_filter = ("account_type", "classification")
    search_fields = ("name", "household__name")


@admin.register(JournalEntry)
class JournalEntryAdmin(ReadOnlyLedgerAdmin):
    list_display = ("effective_at", "description", "entry_type", "household", "created_by")
    list_filter = ("entry_type", "provenance")
    search_fields = ("description", "household__name")


@admin.register(JournalPosting)
class JournalPostingAdmin(ReadOnlyLedgerAdmin):
    list_display = ("entry", "side", "amount", "financial_account", "internal_account")
    list_filter = ("side", "internal_account")
    search_fields = ("entry__description", "financial_account__name")


@admin.register(BalanceSnapshot)
class BalanceSnapshotAdmin(ReadOnlyLedgerAdmin):
    list_display = ("financial_account", "observed_balance", "observed_at", "source")
    list_filter = ("source",)
    search_fields = ("financial_account__name", "household__name")
