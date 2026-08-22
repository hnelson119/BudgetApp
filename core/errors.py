from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

from .logging import current_request_id


def _render_error(request: HttpRequest, *, status: int, title: str, message: str) -> HttpResponse:
    return render(
        request,
        "core/error.html",
        {
            "status": status,
            "title": title,
            "message": message,
            "error_reference": current_request_id(),
        },
        status=status,
    )


def bad_request(request: HttpRequest, exception: Exception) -> HttpResponse:
    return _render_error(
        request,
        status=400,
        title="We couldn't process that request",
        message="Check the information and try again.",
    )


def permission_denied(request: HttpRequest, exception: Exception) -> HttpResponse:
    return _render_error(
        request,
        status=403,
        title="That action isn't available",
        message="Your account does not have access to the requested action.",
    )


def page_not_found(request: HttpRequest, exception: Exception) -> HttpResponse:
    return _render_error(
        request,
        status=404,
        title="Page not found",
        message="The requested page may have moved or no longer exists.",
    )


def server_error(request: HttpRequest) -> HttpResponse:
    return _render_error(
        request,
        status=500,
        title="Something went wrong",
        message="The problem was recorded. You can try again safely.",
    )


def rate_limited(request: HttpRequest, exception: Exception | None = None) -> HttpResponse:
    return _render_error(
        request,
        status=429,
        title="Please wait before trying again",
        message="Too many attempts were received. Try again after a short wait.",
    )
