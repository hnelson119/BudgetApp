from django.contrib import admin

from .models import Category, Household, HouseholdMembership


class MembershipInline(admin.TabularInline):
    model = HouseholdMembership
    extra = 0


@admin.register(Household)
class HouseholdAdmin(admin.ModelAdmin):
    list_display = ("name", "currency", "time_zone", "created_at")
    search_fields = ("name",)
    inlines = (MembershipInline,)


@admin.register(HouseholdMembership)
class HouseholdMembershipAdmin(admin.ModelAdmin):
    list_display = ("household", "user", "is_active", "joined_at")
    list_filter = ("is_active",)
    search_fields = ("household__name", "user__email")


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ("name", "household", "color", "sort_order", "is_archived")
    list_filter = ("is_archived",)
    search_fields = ("name", "household__name")
    readonly_fields = (
        "id",
        "household",
        "name",
        "color",
        "sort_order",
        "is_archived",
        "created_at",
        "updated_at",
    )

    def has_add_permission(self, request: object) -> bool:
        return False

    def has_change_permission(self, request: object, obj: object | None = None) -> bool:
        return False

    def has_delete_permission(self, request: object, obj: object | None = None) -> bool:
        return False
