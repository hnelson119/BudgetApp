from django.urls import path

from imports import views

app_name = "imports"

urlpatterns = [
    path("", views.import_history, name="history"),
    path("new/", views.import_upload, name="upload"),
    path("<uuid:batch_id>/map/", views.import_map, name="batch-map"),
    path("<uuid:batch_id>/", views.import_preview, name="batch-preview"),
    path("<uuid:batch_id>/commit/", views.import_commit, name="batch-commit"),
    path("<uuid:batch_id>/abandon/", views.import_abandon, name="batch-abandon"),
]
