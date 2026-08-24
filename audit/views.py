from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, time, timedelta
from typing import Any
from urllib.parse import urlencode
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Q, QuerySet
from django.http import Http404, HttpRequest, HttpResponse, StreamingHttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_GET

from audit.exports import AuditCSVRow, stream_audit_csv
from audit.forms import AuditFilterForm
from audit.models import AuditCheckpoint, AuditEvent, AuditHead
from audit.services import append_event, verify_household_chain
from core.logging import current_request_id
from households.models import Household
from households.services.access import get_active_household
from identity.models import User
from identity.services.sessions import recent_authentication_is_valid

security_logger = logging.getLogger("security")


@dataclass(frozen=True, slots=True)
class AuditDifference:
    field: str
    before: str
    after: str


def _actor(request: HttpRequest) -> User:
    if not isinstance(request.user, User) or request.user.pk is None:
        raise Http404
    return request.user


def _display(value: object) -> str:
    if value is None:
        return "—"
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return str(value)


def _flatten(value: object, prefix: str = "") -> dict[str, object]:
    if not isinstance(value, dict):
        return {prefix or "Value": value}
    result: dict[str, object] = {}
    for raw_key, nested in value.items():
        key = str(raw_key)
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(nested, dict):
            result.update(_flatten(nested, path))
        else:
            result[path] = nested
    return result


def event_differences(event: AuditEvent) -> tuple[AuditDifference, ...]:
    before = _flatten(event.before_payload)
    after = _flatten(event.after_payload)
    rows: list[AuditDifference] = []
    for field in sorted(set(before) | set(after)):
        old = before.get(field)
        new = after.get(field)
        if old == new:
            continue
        rows.append(
            AuditDifference(
                field=field.replace("_", " ").replace(".", " · ").title(),
                before=_display(old),
                after=_display(new),
            )
        )
    return tuple(rows)


def _event_query(
    *,
    household: Household,
    form: AuditFilterForm,
) -> QuerySet[AuditEvent]:
    events = AuditEvent.objects.filter(household=household).select_related("actor")
    if not form.is_bound:
        return events.order_by("-sequence")
    if not form.is_valid():
        return events.none()
    query = str(form.cleaned_data.get("q", "")).strip()
    action = str(form.cleaned_data.get("action", ""))
    entity_type = str(form.cleaned_data.get("entity_type", ""))
    actor = str(form.cleaned_data.get("actor", ""))
    date_from = form.cleaned_data.get("date_from")
    date_to = form.cleaned_data.get("date_to")
    if query:
        events = events.filter(
            Q(action__icontains=query)
            | Q(entity_type__icontains=query)
            | Q(entity_id__icontains=query)
            | Q(reason__icontains=query)
            | Q(actor__display_name__icontains=query)
            | Q(actor__email__icontains=query)
        )
    if action:
        events = events.filter(action=action)
    if entity_type:
        events = events.filter(entity_type=entity_type)
    if actor == "system":
        events = events.filter(actor_id__isnull=True)
    elif actor:
        try:
            actor_id = UUID(actor)
        except ValueError:
            events = events.none()
        else:
            events = events.filter(actor_id=actor_id)
    zone = ZoneInfo(household.time_zone)
    if date_from:
        events = events.filter(
            occurred_at__gte=timezone.make_aware(datetime.combine(date_from, time.min), zone)
        )
    if date_to:
        events = events.filter(
            occurred_at__lt=timezone.make_aware(
                datetime.combine(date_to + timedelta(days=1), time.min),
                zone,
            )
        )
    return events.order_by("-sequence")


def _integrity_context(household: Household) -> dict[str, object]:
    return {
        "integrity": verify_household_chain(household),
        "integrity_checked_at": timezone.now(),
        "audit_head": AuditHead.objects.filter(household=household).first(),
        "checkpoint": AuditCheckpoint.objects.filter(household=household).first(),
    }


@login_required
@require_GET
def history(request: HttpRequest) -> HttpResponse:
    household = get_active_household(request)
    filter_form = AuditFilterForm(request.GET or None, household=household)
    events = _event_query(household=household, form=filter_form)
    paginator = Paginator(events, 50)
    page = paginator.get_page(request.GET.get("page"))
    page_query = request.GET.copy()
    page_query.pop("page", None)
    export_query = request.GET.copy()
    export_query.pop("page", None)
    return render(
        request,
        "audit/history.html",
        {
            "household": household,
            "filter_form": filter_form,
            "page": page,
            "page_query": page_query.urlencode(),
            "export_query": export_query.urlencode(),
            "current_nav": "audit",
            **_integrity_context(household),
        },
    )


@login_required
@require_GET
def detail(request: HttpRequest, event_id: object) -> HttpResponse:
    household = get_active_household(request)
    event = get_object_or_404(
        AuditEvent.objects.select_related("actor"),
        household=household,
        pk=event_id,
    )
    integrity = verify_household_chain(household)
    if integrity.valid:
        append_event(
            household=household,
            actor=_actor(request),
            action="audit.detail_viewed",
            entity_type="audit.event",
            entity_id=event.pk,
            request_id=current_request_id(),
            after={"viewed_sequence": event.sequence},
        )
    else:
        security_logger.error(
            "Detailed audit access could not be recorded because verification failed.",
            extra={"event": "audit.detail_access_integrity_failed"},
        )
    return render(
        request,
        "audit/detail.html",
        {
            "household": household,
            "event": event,
            "differences": event_differences(event),
            "current_nav": "audit",
            **_integrity_context(household),
        },
    )


def _csv_rows(events: QuerySet[AuditEvent], household: Household) -> Iterator[AuditCSVRow]:
    zone = ZoneInfo(household.time_zone)
    for event in events.iterator(chunk_size=200):
        actor_label = "System"
        if event.actor is not None:
            actor_label = event.actor.display_name or event.actor.email
        yield AuditCSVRow(
            sequence=event.sequence,
            occurred_at=timezone.localtime(event.occurred_at, zone),
            household_timezone=event.household_timezone,
            actor_label=actor_label,
            action=event.action,
            entity_type=event.entity_type,
            entity_id=event.entity_id,
            before=event.before_payload,
            after=event.after_payload,
            reason=event.reason,
            request_id=event.request_id,
            previous_hash=event.previous_hash,
            event_hash=event.event_hash,
        )


@login_required
@require_GET
def export(request: HttpRequest) -> HttpResponse | StreamingHttpResponse:
    household = get_active_household(request)
    if not recent_authentication_is_valid(request):
        query = urlencode({"next": request.get_full_path()})
        return redirect(f"{reverse('identity:reauthenticate')}?{query}")
    integrity = verify_household_chain(household)
    if not integrity.valid:
        security_logger.error(
            "Audit CSV export blocked by audit-integrity failure.",
            extra={"event": "audit.export_integrity_blocked"},
        )
        return HttpResponse(
            "Export is unavailable because audit integrity verification failed.",
            status=409,
            content_type="text/plain; charset=utf-8",
        )
    filter_form = AuditFilterForm(request.GET or None, household=household)
    events = _event_query(household=household, form=filter_form).filter(
        sequence__lte=integrity.event_count
    )
    row_count = events.count()
    export_id = uuid4()
    cleaned: dict[str, Any] = filter_form.cleaned_data if filter_form.is_valid() else {}
    append_event(
        household=household,
        actor=_actor(request),
        action="audit.history_exported",
        entity_type="audit.export",
        entity_id=export_id,
        request_id=current_request_id(),
        after={
            "row_count": row_count,
            "filters": {
                "query_applied": bool(str(cleaned.get("q", "")).strip()),
                "action": str(cleaned.get("action", "")),
                "entity_type": str(cleaned.get("entity_type", "")),
                "actor": str(cleaned.get("actor", "")),
                "date_from": cleaned.get("date_from"),
                "date_to": cleaned.get("date_to"),
            },
        },
    )
    security_logger.info(
        "Protected audit CSV export authorized.",
        extra={
            "event": "audit.history_exported",
            "export_id": str(export_id),
            "row_count": row_count,
        },
    )
    local_now = timezone.localtime(timezone.now(), ZoneInfo(household.time_zone))
    filename = f"budget-audit-{local_now:%Y%m%dT%H%M%S}.csv"
    response = StreamingHttpResponse(
        stream_audit_csv(_csv_rows(events, household)),
        content_type="text/csv; charset=utf-8",
    )
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    return response
