from django.contrib import admin

from .models import PayPeriod, PayPeriodClosingRevision


class ReadOnlyPeriodAdmin(admin.ModelAdmin):
    def has_add_permission(self, request: object) -> bool:
        return False

    def has_change_permission(self, request: object, obj: object | None = None) -> bool:
        return False

    def has_delete_permission(self, request: object, obj: object | None = None) -> bool:
        return False


@admin.register(PayPeriod)
class PayPeriodAdmin(ReadOnlyPeriodAdmin):
    list_display = ("household", "start_date", "next_start_date", "status", "boundary_source")
    list_filter = ("status", "boundary_source")
    search_fields = ("household__name",)


@admin.register(PayPeriodClosingRevision)
class PayPeriodClosingRevisionAdmin(ReadOnlyPeriodAdmin):
    list_display = (
        "pay_period",
        "revision_number",
        "closing_surplus",
        "reserve_delta",
        "created_at",
    )
    search_fields = ("pay_period__household__name",)
