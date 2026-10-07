from django.db import migrations

PROTECT_PAYOFF_HISTORY_SQL = r"""
CREATE TRIGGER payoff_plan_reject_mutation
BEFORE UPDATE OR DELETE ON public.debts_debtpayoffplan
FOR EACH ROW EXECUTE FUNCTION public.reject_debt_history_mutation();
CREATE TRIGGER payoff_plan_reject_truncate
BEFORE TRUNCATE ON public.debts_debtpayoffplan
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_debt_history_mutation();
CREATE TRIGGER payoff_allocation_reject_mutation
BEFORE UPDATE OR DELETE ON public.debts_debtpayoffallocation
FOR EACH ROW EXECUTE FUNCTION public.reject_debt_history_mutation();
CREATE TRIGGER payoff_allocation_reject_truncate
BEFORE TRUNCATE ON public.debts_debtpayoffallocation
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_debt_history_mutation();
"""

UNPROTECT_PAYOFF_HISTORY_SQL = r"""
DROP TRIGGER IF EXISTS payoff_plan_reject_mutation ON public.debts_debtpayoffplan;
DROP TRIGGER IF EXISTS payoff_plan_reject_truncate ON public.debts_debtpayoffplan;
DROP TRIGGER IF EXISTS payoff_allocation_reject_mutation ON public.debts_debtpayoffallocation;
DROP TRIGGER IF EXISTS payoff_allocation_reject_truncate ON public.debts_debtpayoffallocation;
"""


def protect_payoff_history(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(PROTECT_PAYOFF_HISTORY_SQL)


def unprotect_payoff_history(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(UNPROTECT_PAYOFF_HISTORY_SQL)


class Migration(migrations.Migration):
    dependencies = [("debts", "0005_payoff_planning")]
    operations = [migrations.RunPython(protect_payoff_history, unprotect_payoff_history)]
