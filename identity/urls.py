from django.urls import path

from identity import views

app_name = "identity"

urlpatterns = [
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("logout-all/", views.logout_all_devices_view, name="logout-all"),
]
