from django.db import migrations

PROTECT_RECONCILIATIONS_SQL = r"""
CREATE OR REPLACE FUNCTION public.reject_budget_reconciliation_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF pg_catalog.pg_has_role(
        session_user,
        pg_catalog.pg_get_userbyid(
            (SELECT relowner FROM pg_catalog.pg_class WHERE oid = TG_RELID)
        ),
        'MEMBER'
    ) THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        IF TG_OP = 'TRUNCATE' THEN
            RETURN NULL;
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'budget reconciliations cannot be %%', lower(TG_OP)
        USING ERRCODE = '42501';
END
$function$;

DROP TRIGGER IF EXISTS budget_reconciliation_reject_mutation
    ON public.budgets_occurrencereconciliation;
CREATE TRIGGER budget_reconciliation_reject_mutation
BEFORE UPDATE OR DELETE ON public.budgets_occurrencereconciliation
FOR EACH ROW EXECUTE FUNCTION public.reject_budget_reconciliation_mutation();
DROP TRIGGER IF EXISTS budget_reconciliation_reject_truncate
    ON public.budgets_occurrencereconciliation;
CREATE TRIGGER budget_reconciliation_reject_truncate
BEFORE TRUNCATE ON public.budgets_occurrencereconciliation
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_budget_reconciliation_mutation();
"""

UNPROTECT_RECONCILIATIONS_SQL = r"""
DROP TRIGGER IF EXISTS budget_reconciliation_reject_mutation
    ON public.budgets_occurrencereconciliation;
DROP TRIGGER IF EXISTS budget_reconciliation_reject_truncate
    ON public.budgets_occurrencereconciliation;
DROP FUNCTION IF EXISTS public.reject_budget_reconciliation_mutation();
"""


def protect_reconciliations(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(PROTECT_RECONCILIATIONS_SQL)


def unprotect_reconciliations(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(UNPROTECT_RECONCILIATIONS_SQL)


class Migration(migrations.Migration):
    dependencies = [("budgets", "0001_initial")]

    operations = [migrations.RunPython(protect_reconciliations, unprotect_reconciliations)]
