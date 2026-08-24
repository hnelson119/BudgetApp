from django.contrib import admin

from imports.models import ImportBatch, ImportRow


@admin.register(ImportBatch)
class ImportBatchAdmin(admin.ModelAdmin):
    list_display = (
        "original_filename",
        "household",
        "target_account",
        "status",
        "staged_count",
        "committed_count",
        "uploaded_at",
    )
    list_filter = ("status", "uploaded_at")
    search_fields = ("original_filename", "target_account__name")
    readonly_fields = ("file_checksum", "submission_token", "confirmation_token")


@admin.register(ImportRow)
class ImportRowAdmin(admin.ModelAdmin):
    list_display = ("batch", "row_number", "effective_date", "description", "amount", "status")
    list_filter = ("status",)
    search_fields = ("description", "fingerprint")
    raw_id_fields = ("batch", "category", "journal_entry")
