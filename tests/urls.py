from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpRequest, HttpResponse
from django.urls import include, path

from core import errors


def unsafe_error(request: HttpRequest) -> HttpResponse:
    raise RuntimeError("password=not-real-secret")  # pragma: allowlist secret


def unsafe_permission_error(request: HttpRequest) -> HttpResponse:
    raise PermissionDenied("token=not-real-secret")  # pragma: allowlist secret


def concealed_object_denial(request: HttpRequest, object_id: str) -> HttpResponse:
    raise Http404("private object details")


handler400 = errors.bad_request
handler403 = errors.permission_denied
handler404 = errors.page_not_found
handler429 = errors.rate_limited
handler500 = errors.server_error

urlpatterns = [
    path("_test/error/", unsafe_error, name="unsafe-error"),
    path("_test/forbidden/", unsafe_permission_error, name="unsafe-permission"),
    path(
        "_test/hidden/<uuid:object_id>/",
        concealed_object_denial,
        name="concealed-object-denial",
    ),
    path("accounts/", include("identity.urls")),
    path("audit/", include("audit.urls")),
    path("budget/", include("budgets.urls")),
    path("debts/", include("debts.urls")),
    path("goals/", include("goals.urls")),
    path("imports/", include("imports.urls")),
    path("notifications/", include("notifications.urls")),
    path("spending/", include("spending.urls")),
    path("", include("core.urls")),
]
