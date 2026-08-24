from django.db import migrations

PROTECT_DEBT_HISTORY_SQL = r"""
CREATE OR REPLACE FUNCTION public.reject_debt_history_mutation()
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
    RAISE EXCEPTION 'historical debt records cannot be %%', lower(TG_OP)
        USING ERRCODE = '42501';
END
$function$;

DROP TRIGGER IF EXISTS debt_terms_reject_mutation
    ON public.debts_debttermsrevision;
CREATE TRIGGER debt_terms_reject_mutation
BEFORE UPDATE OR DELETE ON public.debts_debttermsrevision
FOR EACH ROW EXECUTE FUNCTION public.reject_debt_history_mutation();
DROP TRIGGER IF EXISTS debt_terms_reject_truncate
    ON public.debts_debttermsrevision;
CREATE TRIGGER debt_terms_reject_truncate
BEFORE TRUNCATE ON public.debts_debttermsrevision
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_debt_history_mutation();

DROP TRIGGER IF EXISTS debt_statement_reject_mutation
    ON public.debts_debtstatement;
CREATE TRIGGER debt_statement_reject_mutation
BEFORE UPDATE OR DELETE ON public.debts_debtstatement
FOR EACH ROW EXECUTE FUNCTION public.reject_debt_history_mutation();
DROP TRIGGER IF EXISTS debt_statement_reject_truncate
    ON public.debts_debtstatement;
CREATE TRIGGER debt_statement_reject_truncate
BEFORE TRUNCATE ON public.debts_debtstatement
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_debt_history_mutation();
"""

UNPROTECT_DEBT_HISTORY_SQL = r"""
DROP TRIGGER IF EXISTS debt_terms_reject_mutation
    ON public.debts_debttermsrevision;
DROP TRIGGER IF EXISTS debt_terms_reject_truncate
    ON public.debts_debttermsrevision;
DROP TRIGGER IF EXISTS debt_statement_reject_mutation
    ON public.debts_debtstatement;
DROP TRIGGER IF EXISTS debt_statement_reject_truncate
    ON public.debts_debtstatement;
DROP FUNCTION IF EXISTS public.reject_debt_history_mutation();
"""


def protect_debt_history(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(PROTECT_DEBT_HISTORY_SQL)


def unprotect_debt_history(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(UNPROTECT_DEBT_HISTORY_SQL)


class Migration(migrations.Migration):
    dependencies = [("debts", "0001_initial")]

    operations = [migrations.RunPython(protect_debt_history, unprotect_debt_history)]
