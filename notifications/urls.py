from django.urls import path

from notifications import views

app_name = "notifications"

urlpatterns = [
    path("", views.notification_list, name="list"),
    path("refresh/", views.refresh, name="refresh"),
    path("preferences/", views.preferences, name="preferences"),
    path("<uuid:notification_id>/read/", views.mark_read, name="read"),
    path("<uuid:notification_id>/dismiss/", views.dismiss, name="dismiss"),
]
