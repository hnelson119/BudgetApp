from django.urls import path

from budgets import views

app_name = "budgets"

urlpatterns = [
    path("<uuid:period_id>/", views.detail, name="detail"),
    path("<uuid:period_id>/variable/add/", views.variable_budget_create, name="variable-create"),
    path("variable/<uuid:budget_id>/edit/", views.variable_budget_edit, name="variable-edit"),
    path("variable/<uuid:budget_id>/delete/", views.variable_budget_delete, name="variable-delete"),
    path("<uuid:period_id>/categories/add/", views.category_create, name="category-create"),
    path("<uuid:period_id>/fixed-expenses/add/", views.fixed_expense_create, name="fixed-create"),
    path("occurrence/<uuid:occurrence_id>/edit/", views.occurrence_edit, name="occurrence-edit"),
    path(
        "occurrence/<uuid:occurrence_id>/move/", views.occurrence_move_view, name="occurrence-move"
    ),
    path(
        "occurrence/<uuid:occurrence_id>/cancel/",
        views.occurrence_cancel_view,
        name="occurrence-cancel",
    ),
    path(
        "occurrence/<uuid:occurrence_id>/reconcile/",
        views.occurrence_reconcile,
        name="occurrence-reconcile",
    ),
    path("<uuid:period_id>/reserve/allocate/", views.reserve_allocate, name="reserve-allocate"),
]
