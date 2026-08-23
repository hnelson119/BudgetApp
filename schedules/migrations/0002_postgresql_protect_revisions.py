from django.db import migrations

PROTECT_SOURCE_REVISIONS_SQL = r"""
CREATE OR REPLACE FUNCTION public.reject_source_revision_mutation()
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
    RAISE EXCEPTION 'source revisions cannot be %%', lower(TG_OP)
        USING ERRCODE = '42501';
END
$function$;

DROP TRIGGER IF EXISTS source_revision_reject_mutation
    ON public.schedules_sourcerevision;
CREATE TRIGGER source_revision_reject_mutation
BEFORE UPDATE OR DELETE ON public.schedules_sourcerevision
FOR EACH ROW EXECUTE FUNCTION public.reject_source_revision_mutation();
DROP TRIGGER IF EXISTS source_revision_reject_truncate
    ON public.schedules_sourcerevision;
CREATE TRIGGER source_revision_reject_truncate
BEFORE TRUNCATE ON public.schedules_sourcerevision
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_source_revision_mutation();
"""

UNPROTECT_SOURCE_REVISIONS_SQL = r"""
DROP TRIGGER IF EXISTS source_revision_reject_mutation
    ON public.schedules_sourcerevision;
DROP TRIGGER IF EXISTS source_revision_reject_truncate
    ON public.schedules_sourcerevision;
DROP FUNCTION IF EXISTS public.reject_source_revision_mutation();
"""


def protect_source_revisions(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(PROTECT_SOURCE_REVISIONS_SQL)


def unprotect_source_revisions(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(UNPROTECT_SOURCE_REVISIONS_SQL)


class Migration(migrations.Migration):
    dependencies = [("schedules", "0001_initial")]

    operations = [migrations.RunPython(protect_source_revisions, unprotect_source_revisions)]
