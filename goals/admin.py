from django.contrib import admin

from goals.models import Goal, GoalContribution, GoalFundingPlan, GoalRevision


class ProtectedHistoryAdmin(admin.ModelAdmin):
    def has_add_permission(self, request):  # type: ignore[no-untyped-def]
        return False

    def has_change_permission(self, request, obj=None):  # type: ignore[no-untyped-def]
        return False

    def has_delete_permission(self, request, obj=None):  # type: ignore[no-untyped-def]
        return False


@admin.register(Goal)
class GoalAdmin(ProtectedHistoryAdmin):
    list_display = ("id", "household", "opening_amount", "created_at")


@admin.register(GoalRevision)
class GoalRevisionAdmin(ProtectedHistoryAdmin):
    list_display = ("name", "goal_type", "status", "priority", "effective_from")
    list_filter = ("goal_type", "status", "automatic_excess_allocation")


@admin.register(GoalFundingPlan)
class GoalFundingPlanAdmin(ProtectedHistoryAdmin):
    list_display = ("goal", "source", "created_at")


@admin.register(GoalContribution)
class GoalContributionAdmin(ProtectedHistoryAdmin):
    list_display = ("goal", "amount", "contribution_type", "effective_at")
    list_filter = ("contribution_type",)
