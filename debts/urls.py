from django.urls import path

from debts import views

app_name = "debts"

urlpatterns = [
    path("", views.debt_list, name="list"),
    path("add/", views.debt_create, name="create"),
    path("projections/", views.payoff_comparison, name="payoff-comparison"),
    path("<uuid:debt_id>/", views.debt_detail, name="detail"),
    path("<uuid:debt_id>/edit/", views.debt_edit, name="edit"),
    path("<uuid:debt_id>/terms/add/", views.debt_terms_create, name="terms-create"),
    path(
        "<uuid:debt_id>/mortgage-plan/add/",
        views.mortgage_plan_create,
        name="mortgage-plan-create",
    ),
    path(
        "<uuid:debt_id>/mortgage-plan/revise/",
        views.mortgage_plan_revise,
        name="mortgage-plan-revise",
    ),
    path(
        "mortgage-occurrence/<uuid:occurrence_id>/extra-principal/",
        views.mortgage_extra_principal,
        name="mortgage-extra-principal",
    ),
    path(
        "<uuid:debt_id>/statements/add/",
        views.debt_statement_create,
        name="statement-create",
    ),
    path(
        "<uuid:debt_id>/statements/<uuid:statement_id>/correct/",
        views.debt_statement_correct,
        name="statement-correct",
    ),
    path("<uuid:debt_id>/status/<str:action>/", views.debt_status, name="status"),
]
