from django.db import migrations

PROTECT_RESERVE_ENTRIES_SQL = r"""
CREATE OR REPLACE FUNCTION public.reject_reserve_entry_mutation()
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
    RAISE EXCEPTION 'reserve entries cannot be %%', lower(TG_OP)
        USING ERRCODE = '42501';
END
$function$;

DROP TRIGGER IF EXISTS reserve_entry_reject_mutation ON public.reserves_reserveentry;
CREATE TRIGGER reserve_entry_reject_mutation
BEFORE UPDATE OR DELETE ON public.reserves_reserveentry
FOR EACH ROW EXECUTE FUNCTION public.reject_reserve_entry_mutation();
DROP TRIGGER IF EXISTS reserve_entry_reject_truncate ON public.reserves_reserveentry;
CREATE TRIGGER reserve_entry_reject_truncate
BEFORE TRUNCATE ON public.reserves_reserveentry
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_reserve_entry_mutation();
"""

UNPROTECT_RESERVE_ENTRIES_SQL = r"""
DROP TRIGGER IF EXISTS reserve_entry_reject_mutation ON public.reserves_reserveentry;
DROP TRIGGER IF EXISTS reserve_entry_reject_truncate ON public.reserves_reserveentry;
DROP FUNCTION IF EXISTS public.reject_reserve_entry_mutation();
"""


def protect_reserve_entries(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(PROTECT_RESERVE_ENTRIES_SQL)


def unprotect_reserve_entries(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(UNPROTECT_RESERVE_ENTRIES_SQL)


class Migration(migrations.Migration):
    dependencies = [("reserves", "0001_initial")]

    operations = [migrations.RunPython(protect_reserve_entries, unprotect_reserve_entries)]
