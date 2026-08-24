from django.urls import path

from audit import views

app_name = "audit"

urlpatterns = [
    path("", views.history, name="history"),
    path("export.csv", views.export, name="export"),
    path("<uuid:event_id>/", views.detail, name="detail"),
]
