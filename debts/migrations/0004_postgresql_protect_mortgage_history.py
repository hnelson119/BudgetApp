from django.db import migrations

PROTECT_MORTGAGE_HISTORY_SQL = r"""
DROP TRIGGER IF EXISTS mortgage_plan_reject_mutation
    ON public.debts_mortgagepaymentplan;
CREATE TRIGGER mortgage_plan_reject_mutation
BEFORE UPDATE OR DELETE ON public.debts_mortgagepaymentplan
FOR EACH ROW EXECUTE FUNCTION public.reject_debt_history_mutation();
DROP TRIGGER IF EXISTS mortgage_plan_reject_truncate
    ON public.debts_mortgagepaymentplan;
CREATE TRIGGER mortgage_plan_reject_truncate
BEFORE TRUNCATE ON public.debts_mortgagepaymentplan
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_debt_history_mutation();

DROP TRIGGER IF EXISTS mortgage_revision_reject_mutation
    ON public.debts_mortgageplanrevision;
CREATE TRIGGER mortgage_revision_reject_mutation
BEFORE UPDATE OR DELETE ON public.debts_mortgageplanrevision
FOR EACH ROW EXECUTE FUNCTION public.reject_debt_history_mutation();
DROP TRIGGER IF EXISTS mortgage_revision_reject_truncate
    ON public.debts_mortgageplanrevision;
CREATE TRIGGER mortgage_revision_reject_truncate
BEFORE TRUNCATE ON public.debts_mortgageplanrevision
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_debt_history_mutation();

DROP TRIGGER IF EXISTS mortgage_component_reject_mutation
    ON public.debts_mortgagepaymentcomponent;
CREATE TRIGGER mortgage_component_reject_mutation
BEFORE UPDATE OR DELETE ON public.debts_mortgagepaymentcomponent
FOR EACH ROW EXECUTE FUNCTION public.reject_debt_history_mutation();
DROP TRIGGER IF EXISTS mortgage_component_reject_truncate
    ON public.debts_mortgagepaymentcomponent;
CREATE TRIGGER mortgage_component_reject_truncate
BEFORE TRUNCATE ON public.debts_mortgagepaymentcomponent
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_debt_history_mutation();

DROP TRIGGER IF EXISTS mortgage_installment_reject_mutation
    ON public.debts_mortgageinstallmentrule;
CREATE TRIGGER mortgage_installment_reject_mutation
BEFORE UPDATE OR DELETE ON public.debts_mortgageinstallmentrule
FOR EACH ROW EXECUTE FUNCTION public.reject_debt_history_mutation();
DROP TRIGGER IF EXISTS mortgage_installment_reject_truncate
    ON public.debts_mortgageinstallmentrule;
CREATE TRIGGER mortgage_installment_reject_truncate
BEFORE TRUNCATE ON public.debts_mortgageinstallmentrule
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_debt_history_mutation();
"""

UNPROTECT_MORTGAGE_HISTORY_SQL = r"""
DROP TRIGGER IF EXISTS mortgage_plan_reject_mutation
    ON public.debts_mortgagepaymentplan;
DROP TRIGGER IF EXISTS mortgage_plan_reject_truncate
    ON public.debts_mortgagepaymentplan;
DROP TRIGGER IF EXISTS mortgage_revision_reject_mutation
    ON public.debts_mortgageplanrevision;
DROP TRIGGER IF EXISTS mortgage_revision_reject_truncate
    ON public.debts_mortgageplanrevision;
DROP TRIGGER IF EXISTS mortgage_component_reject_mutation
    ON public.debts_mortgagepaymentcomponent;
DROP TRIGGER IF EXISTS mortgage_component_reject_truncate
    ON public.debts_mortgagepaymentcomponent;
DROP TRIGGER IF EXISTS mortgage_installment_reject_mutation
    ON public.debts_mortgageinstallmentrule;
DROP TRIGGER IF EXISTS mortgage_installment_reject_truncate
    ON public.debts_mortgageinstallmentrule;
"""


def protect_mortgage_history(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(PROTECT_MORTGAGE_HISTORY_SQL)


def unprotect_mortgage_history(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(UNPROTECT_MORTGAGE_HISTORY_SQL)


class Migration(migrations.Migration):
    dependencies = [("debts", "0003_mortgagepaymentplan_mortgageplanrevision_and_more")]

    operations = [migrations.RunPython(protect_mortgage_history, unprotect_mortgage_history)]
