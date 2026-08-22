from django.contrib import admin
from django.urls import include, path

handler400 = "core.errors.bad_request"
handler403 = "core.errors.permission_denied"
handler404 = "core.errors.page_not_found"
handler429 = "core.errors.rate_limited"
handler500 = "core.errors.server_error"

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("identity.urls")),
    path("", include("core.urls")),
]
