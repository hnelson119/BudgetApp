from django.http import HttpRequest, HttpResponse
from django.urls import include, path

from core import errors


def unsafe_error(request: HttpRequest) -> HttpResponse:
    raise RuntimeError("password=not-real-secret")  # pragma: allowlist secret


handler400 = errors.bad_request
handler403 = errors.permission_denied
handler404 = errors.page_not_found
handler429 = errors.rate_limited
handler500 = errors.server_error

urlpatterns = [
    path("_test/error/", unsafe_error, name="unsafe-error"),
    path("accounts/", include("identity.urls")),
    path("audit/", include("audit.urls")),
    path("budget/", include("budgets.urls")),
    path("debts/", include("debts.urls")),
    path("imports/", include("imports.urls")),
    path("spending/", include("spending.urls")),
    path("", include("core.urls")),
]
