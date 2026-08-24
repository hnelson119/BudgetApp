from __future__ import annotations

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.http import Http404, HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from core.logging import current_request_id
from households.services.access import get_active_household
from identity.models import User
from notifications.forms import NotificationPreferenceForm
from notifications.models import Notification, NotificationPreference
from notifications.services import (
    dismiss_notification,
    mark_notification_read,
    notifications_for_user,
    refresh_household_notifications,
    update_preferences,
)


def _actor(request: HttpRequest) -> User:
    if not isinstance(request.user, User) or request.user.pk is None:
        raise Http404
    return request.user


@login_required
@require_GET
def notification_list(request: HttpRequest) -> HttpResponse:
    household = get_active_household(request)
    include_history = request.GET.get("status") == "all"
    notifications = notifications_for_user(
        household=household,
        user=_actor(request),
        include_history=include_history,
    )[:200]
    return render(
        request,
        "notifications/list.html",
        {
            "household": household,
            "notifications": notifications,
            "include_history": include_history,
            "current_nav": "notifications",
        },
    )


@login_required
@require_POST
def refresh(request: HttpRequest) -> HttpResponse:
    household = get_active_household(request)
    result = refresh_household_notifications(household=household)
    messages.success(
        request,
        f"Notification check complete: {result.created} new, {result.resolved} resolved.",
    )
    return redirect("notifications:list")


def _notification_for_request(request: HttpRequest, notification_id: object) -> Notification:
    household = get_active_household(request)
    return get_object_or_404(
        Notification,
        pk=notification_id,
        household=household,
        recipient=request.user,
    )


@login_required
@require_POST
def mark_read(request: HttpRequest, notification_id: object) -> HttpResponse:
    notification = _notification_for_request(request, notification_id)
    mark_notification_read(
        notification=notification,
        actor=_actor(request),
        request_id=current_request_id(),
    )
    return redirect(notification.internal_action_url or "notifications:list")


@login_required
@require_POST
def dismiss(request: HttpRequest, notification_id: object) -> HttpResponse:
    notification = _notification_for_request(request, notification_id)
    dismiss_notification(
        notification=notification,
        actor=_actor(request),
        request_id=current_request_id(),
    )
    messages.success(request, "Notification dismissed. It remains in notification history.")
    return redirect("notifications:list")


@login_required
@require_http_methods(("GET", "POST"))
def preferences(request: HttpRequest) -> HttpResponse:
    household = get_active_household(request)
    actor = _actor(request)
    preference, _ = NotificationPreference.objects.get_or_create(
        household=household,
        user=actor,
    )
    form = NotificationPreferenceForm(request.POST or None, instance=preference)
    if request.method == "POST" and form.is_valid():
        try:
            update_preferences(
                household=household,
                actor=actor,
                values={name: form.cleaned_data[name] for name in form.fields},
                request_id=current_request_id(),
            )
        except ValidationError as error:
            form.add_error(None, error)
        else:
            messages.success(request, "Notification preferences updated.")
            return redirect("notifications:list")
    return render(
        request,
        "notifications/preferences.html",
        {
            "household": household,
            "form": form,
            "current_nav": "notifications",
        },
    )
