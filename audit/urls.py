from django.urls import path

from audit import views

app_name = "audit"

urlpatterns = [path("", views.history, name="history")]
