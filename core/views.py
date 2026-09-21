import logging
from uuid import UUID
from zoneinfo import ZoneInfo

from django.contrib.auth.decorators import login_required
from django.db import DatabaseError, connection
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.utils import timezone

from budgets.services.summary import build_period_summary
from goals.services import goal_progress_rows
from households.services.access import get_active_household
from periods.models import PayPeriod

availability_logger = logging.getLogger("budget.request")


@login_required
def home(request: HttpRequest) -> HttpResponse:
    household = get_active_household(request)
    today = timezone.localdate(timezone=ZoneInfo(household.time_zone))
    period = None
    selected_period_id = request.GET.get("period", "")
    if selected_period_id:
        try:
            selected_period_uuid = UUID(selected_period_id)
        except (TypeError, ValueError, AttributeError):
            selected_period_uuid = None
        if selected_period_uuid is not None:
            period = PayPeriod.objects.filter(
                household=household,
                pk=selected_period_uuid,
            ).first()
    if period is None:
        period = PayPeriod.objects.filter(
            household=household,
            start_date__lte=today,
            next_start_date__gt=today,
        ).first()
    if period is None:
        period = PayPeriod.objects.filter(household=household, start_date__gt=today).first()
    context: dict[str, object] = {
        "household": household,
        "period": period,
        "current_nav": "overview",
    }
    if period is not None:
        context.update(
            {
                "summary": build_period_summary(
                    household=household,
                    period=period,
                    today=today,
                ),
                "goal_progress": goal_progress_rows(
                    household=household,
                    on_date=period.start_date,
                ),
                "previous_period": PayPeriod.objects.filter(
                    household=household,
                    start_date__lt=period.start_date,
                )
                .order_by("-start_date")
                .first(),
                "next_period": PayPeriod.objects.filter(
                    household=household,
                    start_date__gt=period.start_date,
                )
                .order_by("start_date")
                .first(),
            }
        )
    return render(request, "core/home.html", context)


def live(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"status": "ok"})


def ready(request: HttpRequest) -> JsonResponse:
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
    except DatabaseError:
        availability_logger.warning("Database readiness check failed.")
        response = JsonResponse(
            {"status": "unavailable", "database": "unavailable"},
            status=503,
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Retry-After"] = "5"
        return response
    return JsonResponse({"status": "ready", "database": "ok"})
