from django.contrib.auth.decorators import login_required
from django.db import connection
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render

from households.services.access import get_active_household


@login_required
def home(request: HttpRequest) -> HttpResponse:
    household = get_active_household(request)
    return render(request, "core/home.html", {"household": household})


def live(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"status": "ok"})


def ready(request: HttpRequest) -> JsonResponse:
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1")
        cursor.fetchone()
    return JsonResponse({"status": "ready", "database": "ok"})
