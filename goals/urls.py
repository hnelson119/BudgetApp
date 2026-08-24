from django.urls import path

from goals import views

app_name = "goals"

urlpatterns = [
    path("", views.goal_list, name="list"),
    path("add/", views.goal_create, name="create"),
    path(
        "priority-allocation/<uuid:period_id>/",
        views.priority_allocate,
        name="priority-allocate",
    ),
    path("<uuid:goal_id>/", views.goal_detail, name="detail"),
    path("<uuid:goal_id>/revise/", views.goal_revise, name="revise"),
    path("<uuid:goal_id>/status/<str:status>/", views.goal_status, name="status"),
    path("<uuid:goal_id>/contribute/", views.goal_contribute, name="contribute"),
    path(
        "<uuid:goal_id>/occurrence/<uuid:occurrence_id>/contribute/",
        views.goal_contribute,
        name="occurrence-contribute",
    ),
    path(
        "<uuid:goal_id>/reserve/<uuid:period_id>/",
        views.goal_reserve_allocate,
        name="reserve-allocate",
    ),
]
