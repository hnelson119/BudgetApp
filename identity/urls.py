from django.urls import path

from identity import views

app_name = "identity"

urlpatterns = [
    path("login/", views.login_view, name="login"),
    path("mfa/verify/", views.mfa_verify_view, name="mfa-verify"),
    path("mfa/enroll/", views.mfa_enroll_view, name="mfa-enroll"),
    path(
        "mfa/recovery-codes/confirm/",
        views.mfa_recovery_confirm_view,
        name="mfa-recovery-confirm",
    ),
    path(
        "mfa/enroll/restart/",
        views.mfa_enrollment_restart_view,
        name="mfa-enrollment-restart",
    ),
    path("reauthenticate/", views.reauthenticate_view, name="reauthenticate"),
    path("logout/", views.logout_view, name="logout"),
    path("logout-all/", views.logout_all_devices_view, name="logout-all"),
]
