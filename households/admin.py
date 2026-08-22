from django.contrib import admin

from .models import Household, HouseholdMembership


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
