from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

from audit.models import AuditCheckpoint, AuditEvent
from audit.services import verify_household_chain
from households.services.access import get_active_household


@login_required
def history(request: HttpRequest) -> HttpResponse:
    household = get_active_household(request)
    integrity = verify_household_chain(household)
    events = list(
        AuditEvent.objects.filter(household=household)
        .select_related("actor")
        .order_by("-sequence")[:100]
    )
    checkpoint = AuditCheckpoint.objects.filter(household=household).first()
    return render(
        request,
        "audit/history.html",
        {
            "household": household,
            "integrity": integrity,
            "events": events,
            "checkpoint": checkpoint,
        },
    )
