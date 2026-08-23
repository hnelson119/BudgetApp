from django.contrib import admin

from budgets.models import OccurrenceReconciliation, VariableBudget


@admin.register(VariableBudget)
class VariableBudgetAdmin(admin.ModelAdmin):
    list_display = ("pay_period", "category", "planned_amount", "updated_at")
    list_filter = ("pay_period__household",)
    search_fields = ("category__name",)


@admin.register(OccurrenceReconciliation)
class OccurrenceReconciliationAdmin(admin.ModelAdmin):
    list_display = ("occurrence", "journal_entry", "amount", "created_at")
    list_filter = ("household",)
    readonly_fields = tuple(field.name for field in OccurrenceReconciliation._meta.fields)

    def has_add_permission(self, request) -> bool:  # type: ignore[no-untyped-def]
        return False

    def has_change_permission(self, request, obj=None) -> bool:  # type: ignore[no-untyped-def]
        return False

    def has_delete_permission(self, request, obj=None) -> bool:  # type: ignore[no-untyped-def]
        return False
