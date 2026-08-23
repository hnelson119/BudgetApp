from django.contrib import admin

from .models import (
    ExpenseSourceDetail,
    IncomeSourceDetail,
    Occurrence,
    RecurringSource,
    SourceRevision,
)


class ReadOnlyScheduleAdmin(admin.ModelAdmin):
    def has_add_permission(self, request: object) -> bool:
        return False

    def has_change_permission(self, request: object, obj: object | None = None) -> bool:
        return False

    def has_delete_permission(self, request: object, obj: object | None = None) -> bool:
        return False


@admin.register(RecurringSource)
class RecurringSourceAdmin(ReadOnlyScheduleAdmin):
    list_display = ("name", "household", "kind", "archived_from", "archived_at")
    list_filter = ("kind",)
    search_fields = ("name", "household__name")


@admin.register(IncomeSourceDetail)
class IncomeSourceDetailAdmin(ReadOnlyScheduleAdmin):
    list_display = ("source", "starts_budget_period", "is_variable")
    list_filter = ("starts_budget_period", "is_variable")


@admin.register(ExpenseSourceDetail)
class ExpenseSourceDetailAdmin(ReadOnlyScheduleAdmin):
    list_display = ("source", "category", "is_required")
    list_filter = ("is_required",)


@admin.register(SourceRevision)
class SourceRevisionAdmin(ReadOnlyScheduleAdmin):
    list_display = (
        "source",
        "revision_number",
        "effective_from",
        "frequency",
        "expected_amount",
    )
    list_filter = ("frequency", "adjustment_policy")
    search_fields = ("source__name", "source__household__name")


@admin.register(Occurrence)
class OccurrenceAdmin(ReadOnlyScheduleAdmin):
    list_display = ("source", "expected_date", "planned_amount", "pay_period", "status")
    list_filter = ("status", "source__kind")
    search_fields = ("source__name", "source__household__name")
