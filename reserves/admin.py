from django.contrib import admin

from .models import CardPaymentReserveEntry, ReserveEntry


@admin.register(ReserveEntry)
class ReserveEntryAdmin(admin.ModelAdmin):
    list_display = (
        "household",
        "entry_type",
        "amount",
        "source_period",
        "posting_period",
        "allocation_label",
        "created_at",
    )
    list_filter = ("entry_type",)
    search_fields = ("household__name",)

    def has_add_permission(self, request: object) -> bool:
        return False

    def has_change_permission(self, request: object, obj: object | None = None) -> bool:
        return False

    def has_delete_permission(self, request: object, obj: object | None = None) -> bool:
        return False


@admin.register(CardPaymentReserveEntry)
class CardPaymentReserveEntryAdmin(admin.ModelAdmin):
    list_display = (
        "card_account",
        "entry_type",
        "amount",
        "payment_amount",
        "reserve_settlement",
        "debt_payoff",
        "pay_period",
        "created_at",
    )
    list_filter = ("entry_type",)
    search_fields = ("household__name", "card_account__name", "journal_entry__description")

    def has_add_permission(self, request: object) -> bool:
        return False

    def has_change_permission(self, request: object, obj: object | None = None) -> bool:
        return False

    def has_delete_permission(self, request: object, obj: object | None = None) -> bool:
        return False
