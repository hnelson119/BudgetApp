from django.db import migrations

PROTECT_PERIOD_SQL = r"""
CREATE OR REPLACE FUNCTION public.reject_period_closing_mutation()
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
    RAISE EXCEPTION 'pay period closing revisions cannot be %%', lower(TG_OP)
        USING ERRCODE = '42501';
END
$function$;

DROP TRIGGER IF EXISTS period_closing_reject_mutation
    ON public.periods_payperiodclosingrevision;
CREATE TRIGGER period_closing_reject_mutation
BEFORE UPDATE OR DELETE ON public.periods_payperiodclosingrevision
FOR EACH ROW EXECUTE FUNCTION public.reject_period_closing_mutation();
DROP TRIGGER IF EXISTS period_closing_reject_truncate
    ON public.periods_payperiodclosingrevision;
CREATE TRIGGER period_closing_reject_truncate
BEFORE TRUNCATE ON public.periods_payperiodclosingrevision
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_period_closing_mutation();

CREATE OR REPLACE FUNCTION public.enforce_pay_period_no_overlap()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(NEW.household_id::text, 4104)
    );
    IF EXISTS (
        SELECT 1
          FROM public.periods_payperiod AS other
         WHERE other.household_id = NEW.household_id
           AND other.id <> NEW.id
           AND other.start_date < NEW.next_start_date
           AND other.next_start_date > NEW.start_date
    ) THEN
        RAISE EXCEPTION 'pay periods for one household cannot overlap'
            USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$function$;

DROP TRIGGER IF EXISTS period_reject_overlap ON public.periods_payperiod;
CREATE TRIGGER period_reject_overlap
BEFORE INSERT OR UPDATE OF household_id, start_date, next_start_date
ON public.periods_payperiod
FOR EACH ROW EXECUTE FUNCTION public.enforce_pay_period_no_overlap();
"""

UNPROTECT_PERIOD_SQL = r"""
DROP TRIGGER IF EXISTS period_reject_overlap ON public.periods_payperiod;
DROP FUNCTION IF EXISTS public.enforce_pay_period_no_overlap();
DROP TRIGGER IF EXISTS period_closing_reject_mutation
    ON public.periods_payperiodclosingrevision;
DROP TRIGGER IF EXISTS period_closing_reject_truncate
    ON public.periods_payperiodclosingrevision;
DROP FUNCTION IF EXISTS public.reject_period_closing_mutation();
"""


def protect_period_history(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(PROTECT_PERIOD_SQL)


def unprotect_period_history(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(UNPROTECT_PERIOD_SQL)


class Migration(migrations.Migration):
    dependencies = [("periods", "0001_initial")]

    operations = [migrations.RunPython(protect_period_history, unprotect_period_history)]
