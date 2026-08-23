from __future__ import annotations

import logging
from typing import cast

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from households.services.access import get_active_household
from identity.models import User
from imports.forms import CSVAbandonForm, CSVCommitForm, CSVMappingForm, CSVUploadForm
from imports.models import ImportBatch
from imports.services import (
    abandon_import_batch,
    commit_import_batch,
    preview_import_batch,
    stage_csv_import,
)

security_logger = logging.getLogger("security")


def _actor(request: HttpRequest) -> User:
    if not isinstance(request.user, User):
        raise PermissionDenied
    return request.user


def _request_id(request: HttpRequest) -> str:
    return str(request.request_id)  # type: ignore[attr-defined]


def _batch(request: HttpRequest, batch_id: str) -> ImportBatch:
    household = get_active_household(request)
    return get_object_or_404(
        ImportBatch.objects.select_related("household", "target_account", "created_by"),
        pk=batch_id,
        household=household,
    )


def _batch_destination(batch: ImportBatch) -> str:
    if batch.status == ImportBatch.Status.UPLOADED:
        return "imports:batch-map"
    return "imports:batch-preview"


@login_required
@require_GET
def import_history(request: HttpRequest) -> HttpResponse:
    household = get_active_household(request)
    batches = ImportBatch.objects.filter(household=household).select_related(
        "target_account",
        "created_by",
    )[:100]
    return render(
        request,
        "imports/import_history.html",
        {
            "household": household,
            "batches": batches,
            "current_nav": "spending",
        },
    )


@login_required
@require_http_methods(("GET", "POST"))
def import_upload(request: HttpRequest) -> HttpResponse:
    household = get_active_household(request)
    form = CSVUploadForm(request.POST or None, request.FILES or None, household=household)
    if request.method == "POST" and form.is_valid():
        try:
            batch = stage_csv_import(
                household=household,
                actor=_actor(request),
                target_account=form.cleaned_data["target_account"],
                upload=form.cleaned_data["csv_file"],
                submission_token=form.cleaned_data["submission_token"],
                request_id=_request_id(request),
            )
        except ValidationError as error:
            security_logger.warning(
                "CSV upload rejected.",
                extra={"event": "import.upload_rejected"},
            )
            form.add_error("csv_file", error)
        else:
            messages.success(request, "CSV validated and staged. No transactions exist yet.")
            return redirect(_batch_destination(batch), batch_id=batch.pk)
    return render(
        request,
        "imports/import_upload.html",
        {
            "household": household,
            "form": form,
            "current_nav": "spending",
        },
    )


@login_required
@require_http_methods(("GET", "POST"))
def import_map(request: HttpRequest, batch_id: str) -> HttpResponse:
    batch = _batch(request, batch_id)
    if batch.status == ImportBatch.Status.ABANDONED:
        raise Http404("This staged import was abandoned.")
    if batch.status == ImportBatch.Status.COMMITTED:
        return redirect("imports:batch-preview", batch_id=batch.pk)
    form = CSVMappingForm(request.POST or None, batch=batch)
    if request.method == "POST" and form.is_valid():
        try:
            preview_import_batch(
                batch=batch,
                actor=_actor(request),
                date_column=cast(str, form.cleaned_data["date_column"]),
                description_column=cast(str, form.cleaned_data["description_column"]),
                amount_column=cast(str, form.cleaned_data["amount_column"]),
                category_column=cast(str, form.cleaned_data["category_column"]),
                date_format=cast(str, form.cleaned_data["date_format"]),
                expense_sign=cast(str, form.cleaned_data["expense_sign"]),
                default_category=form.cleaned_data["default_category"],
                request_id=_request_id(request),
            )
        except ValidationError as error:
            security_logger.warning(
                "CSV preview rejected.",
                extra={"event": "import.preview_rejected", "import_id": str(batch.pk)},
            )
            form.add_error(None, error)
        else:
            messages.success(request, "Preview refreshed. Review every result before confirming.")
            return redirect("imports:batch-preview", batch_id=batch.pk)
    return render(
        request,
        "imports/import_mapping.html",
        {
            "household": batch.household,
            "batch": batch,
            "form": form,
            "current_nav": "spending",
        },
    )


@login_required
@require_GET
def import_preview(request: HttpRequest, batch_id: str) -> HttpResponse:
    batch = _batch(request, batch_id)
    if batch.status == ImportBatch.Status.UPLOADED:
        return redirect("imports:batch-map", batch_id=batch.pk)
    rows = batch.rows.select_related("category", "journal_entry").order_by("row_number")[:100]
    return render(
        request,
        "imports/import_preview.html",
        {
            "household": batch.household,
            "batch": batch,
            "rows": rows,
            "rows_truncated": batch.staged_count > 100,
            "commit_form": CSVCommitForm(initial={"confirmation_token": batch.confirmation_token}),
            "abandon_form": CSVAbandonForm(),
            "current_nav": "spending",
        },
    )


@login_required
@require_POST
def import_commit(request: HttpRequest, batch_id: str) -> HttpResponse:
    batch = _batch(request, batch_id)
    form = CSVCommitForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Confirm the reviewed import before committing it.")
        return redirect("imports:batch-preview", batch_id=batch.pk)
    try:
        result = commit_import_batch(
            batch=batch,
            actor=_actor(request),
            confirmation_token=form.cleaned_data["confirmation_token"],
            request_id=_request_id(request),
        )
    except ValidationError as error:
        security_logger.warning(
            "CSV commit rejected.",
            extra={"event": "import.commit_rejected", "import_id": str(batch.pk)},
        )
        messages.error(request, error.messages[0])
    else:
        if result.already_committed:
            messages.info(request, "This CSV import was already committed.")
        else:
            messages.success(request, f"Imported {len(result.entries)} protected transactions.")
    return redirect("imports:batch-preview", batch_id=batch.pk)


@login_required
@require_POST
def import_abandon(request: HttpRequest, batch_id: str) -> HttpResponse:
    batch = _batch(request, batch_id)
    form = CSVAbandonForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Confirm that you want to discard the staged import.")
        return redirect(_batch_destination(batch), batch_id=batch.pk)
    try:
        abandon_import_batch(
            batch=batch,
            actor=_actor(request),
            request_id=_request_id(request),
        )
    except ValidationError as error:
        security_logger.warning(
            "CSV abandonment rejected.",
            extra={"event": "import.abandon_rejected", "import_id": str(batch.pk)},
        )
        messages.error(request, error.messages[0])
        return redirect("imports:batch-preview", batch_id=batch.pk)
    messages.success(request, "Staged import discarded; its raw row data was removed.")
    return redirect("imports:history")
