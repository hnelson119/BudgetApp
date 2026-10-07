from django.db import migrations

PROTECT_PROMOTIONS_SQL = r"""
CREATE TRIGGER debt_promotion_reject_mutation
BEFORE UPDATE OR DELETE ON public.debts_debtpromotionrevision
FOR EACH ROW EXECUTE FUNCTION public.reject_debt_history_mutation();
CREATE TRIGGER debt_promotion_reject_truncate
BEFORE TRUNCATE ON public.debts_debtpromotionrevision
FOR EACH STATEMENT EXECUTE FUNCTION public.reject_debt_history_mutation();
"""

UNPROTECT_PROMOTIONS_SQL = r"""
DROP TRIGGER IF EXISTS debt_promotion_reject_mutation ON public.debts_debtpromotionrevision;
DROP TRIGGER IF EXISTS debt_promotion_reject_truncate ON public.debts_debtpromotionrevision;
"""


def protect_promotions(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(PROTECT_PROMOTIONS_SQL)


def unprotect_promotions(apps, schema_editor) -> None:  # type: ignore[no-untyped-def]
    if schema_editor.connection.vendor == "postgresql":
        schema_editor.execute(UNPROTECT_PROMOTIONS_SQL)


class Migration(migrations.Migration):
    dependencies = [("debts", "0007_debtpromotionrevision")]
    operations = [migrations.RunPython(protect_promotions, unprotect_promotions)]
