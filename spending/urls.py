from django.urls import path

from spending import views

app_name = "spending"

urlpatterns = [
    path("", views.transaction_list, name="transaction-list"),
    path("expenses/add/", views.expense_create, name="expense-create"),
    path("income/add/", views.income_create, name="income-create"),
    path("accounts/add/", views.account_create, name="account-create"),
    path("<uuid:entry_id>/", views.transaction_detail, name="transaction-detail"),
    path("<uuid:entry_id>/reverse/", views.transaction_reverse, name="transaction-reverse"),
]
