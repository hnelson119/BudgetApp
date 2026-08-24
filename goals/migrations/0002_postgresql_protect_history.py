from django.db import migrations

PROTECT_GOAL_HISTORY_SQL = r"""
CREATE OR REPLACE FUNCTION public.reject_goal_history_mutation()
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
    RAISE EXCEPTION 'historical goal records cannot be %%', lower(TG_OP)
        USING ERRCODE = '42501';
END
$function$;

DROP TRIGGER IF EXISTS goal_reject_mutation ON public.goals_goal;
CREATE TRIGGER goal_reject_mutation
BEFORE UPDATE OR DELETE ON public.goals_goal
FOR EACH ROW EXECUTE FUNCTION public.reject_goal_history_mutation();
DROP TRIGGER IF EXISTS goal_reject_truncate ON public.goals_goal;
CREATE TRIGGER goal_reject_truncate
BEFORE TRUNCATE ON public.goals_goal
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_goal_history_mutation();

DROP TRIGGER IF EXISTS goal_revision_reject_mutation ON public.goals_goalrevision;
CREATE TRIGGER goal_revision_reject_mutation
BEFORE UPDATE OR DELETE ON public.goals_goalrevision
FOR EACH ROW EXECUTE FUNCTION public.reject_goal_history_mutation();
DROP TRIGGER IF EXISTS goal_revision_reject_truncate ON public.goals_goalrevision;
CREATE TRIGGER goal_revision_reject_truncate
BEFORE TRUNCATE ON public.goals_goalrevision
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_goal_history_mutation();

DROP TRIGGER IF EXISTS goal_plan_reject_mutation ON public.goals_goalfundingplan;
CREATE TRIGGER goal_plan_reject_mutation
BEFORE UPDATE OR DELETE ON public.goals_goalfundingplan
FOR EACH ROW EXECUTE FUNCTION public.reject_goal_history_mutation();
DROP TRIGGER IF EXISTS goal_plan_reject_truncate ON public.goals_goalfundingplan;
CREATE TRIGGER goal_plan_reject_truncate
BEFORE TRUNCATE ON public.goals_goalfundingplan
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_goal_history_mutation();

DROP TRIGGER IF EXISTS goal_contribution_reject_mutation ON public.goals_goalcontribution;
CREATE TRIGGER goal_contribution_reject_mutation
BEFORE UPDATE OR DELETE ON public.goals_goalcontribution
FOR EACH ROW EXECUTE FUNCTION public.reject_goal_history_mutation();
DROP TRIGGER IF EXISTS goal_contribution_reject_truncate ON public.goals_goalcontribution;
CREATE TRIGGER goal_contribution_reject_truncate
BEFORE TRUNCATE ON public.goals_goalcontribution
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_goal_history_mutation();
"""

UNPROTECT_GOAL_HISTORY_SQL = r"""
DROP TRIGGER IF EXISTS goal_reject_mutation ON public.goals_goal;
DROP TRIGGER IF EXISTS goal_reject_truncate ON public.goals_goal;
DROP TRIGGER IF EXISTS goal_revision_reject_mutation ON public.goals_goalrevision;
DROP TRIGGER IF EXISTS goal_revision_reject_truncate ON public.goals_goalrevision;
DROP TRIGGER IF EXISTS goal_plan_reject_mutation ON public.goals_goalfundingplan;
DROP TRIGGER IF EXISTS goal_plan_reject_truncate ON public.goals_goalfundingplan;
DROP TRIGGER IF EXISTS goal_contribution_reject_mutation ON public.goals_goalcontribution;
DROP TRIGGER IF EXISTS goal_contribution_reject_truncate ON public.goals_goalcontribution;
DROP FUNCTION IF EXISTS public.reject_goal_history_mutation();
"""


def protect_goal_history(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(PROTECT_GOAL_HISTORY_SQL)


def unprotect_goal_history(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(UNPROTECT_GOAL_HISTORY_SQL)


class Migration(migrations.Migration):
    dependencies = [("goals", "0001_initial")]

    operations = [migrations.RunPython(protect_goal_history, unprotect_goal_history)]
