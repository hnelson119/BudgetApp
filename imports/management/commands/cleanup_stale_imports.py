from django.core.management.base import BaseCommand

from imports.services import expire_stale_import_batches


class Command(BaseCommand):
    help = "Scrub raw row data from CSV imports that exceeded the staging retention window."

    def handle(self, *args: object, **options: object) -> None:
        expired = expire_stale_import_batches()
        self.stdout.write(f"Expired staged CSV imports: {expired}")
