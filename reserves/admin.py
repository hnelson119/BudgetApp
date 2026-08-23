from django.contrib import admin

from .models import ReserveEntry


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
