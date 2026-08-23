from django.db import migrations

PROTECT_LEDGER_HISTORY_SQL = r"""
CREATE OR REPLACE FUNCTION public.reject_committed_ledger_mutation()
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
    RAISE EXCEPTION 'committed ledger records cannot be %%', lower(TG_OP)
        USING ERRCODE = '42501';
END
$function$;

DROP TRIGGER IF EXISTS ledger_entry_reject_mutation ON public.ledger_journalentry;
CREATE TRIGGER ledger_entry_reject_mutation
BEFORE UPDATE OR DELETE ON public.ledger_journalentry
FOR EACH ROW EXECUTE FUNCTION public.reject_committed_ledger_mutation();
DROP TRIGGER IF EXISTS ledger_entry_reject_truncate ON public.ledger_journalentry;
CREATE TRIGGER ledger_entry_reject_truncate
BEFORE TRUNCATE ON public.ledger_journalentry
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_committed_ledger_mutation();

DROP TRIGGER IF EXISTS ledger_posting_reject_mutation ON public.ledger_journalposting;
CREATE TRIGGER ledger_posting_reject_mutation
BEFORE UPDATE OR DELETE ON public.ledger_journalposting
FOR EACH ROW EXECUTE FUNCTION public.reject_committed_ledger_mutation();
DROP TRIGGER IF EXISTS ledger_posting_reject_truncate ON public.ledger_journalposting;
CREATE TRIGGER ledger_posting_reject_truncate
BEFORE TRUNCATE ON public.ledger_journalposting
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_committed_ledger_mutation();

DROP TRIGGER IF EXISTS ledger_snapshot_reject_mutation ON public.ledger_balancesnapshot;
CREATE TRIGGER ledger_snapshot_reject_mutation
BEFORE UPDATE OR DELETE ON public.ledger_balancesnapshot
FOR EACH ROW EXECUTE FUNCTION public.reject_committed_ledger_mutation();
DROP TRIGGER IF EXISTS ledger_snapshot_reject_truncate ON public.ledger_balancesnapshot;
CREATE TRIGGER ledger_snapshot_reject_truncate
BEFORE TRUNCATE ON public.ledger_balancesnapshot
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_committed_ledger_mutation();
"""

UNPROTECT_LEDGER_HISTORY_SQL = r"""
DROP TRIGGER IF EXISTS ledger_entry_reject_mutation ON public.ledger_journalentry;
DROP TRIGGER IF EXISTS ledger_entry_reject_truncate ON public.ledger_journalentry;
DROP TRIGGER IF EXISTS ledger_posting_reject_mutation ON public.ledger_journalposting;
DROP TRIGGER IF EXISTS ledger_posting_reject_truncate ON public.ledger_journalposting;
DROP TRIGGER IF EXISTS ledger_snapshot_reject_mutation ON public.ledger_balancesnapshot;
DROP TRIGGER IF EXISTS ledger_snapshot_reject_truncate ON public.ledger_balancesnapshot;
DROP FUNCTION IF EXISTS public.reject_committed_ledger_mutation();
"""


def protect_ledger_history(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(PROTECT_LEDGER_HISTORY_SQL)


def unprotect_ledger_history(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(UNPROTECT_LEDGER_HISTORY_SQL)


class Migration(migrations.Migration):
    dependencies = [("ledger", "0001_initial")]

    operations = [
        migrations.RunPython(protect_ledger_history, unprotect_ledger_history),
    ]
