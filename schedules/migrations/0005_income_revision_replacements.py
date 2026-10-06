from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [("schedules", "0004_expensesourcedetail")]

    operations = [
        migrations.RemoveConstraint(
            model_name="sourcerevision",
            name="schedules_revision_source_effective_unique",
        ),
    ]
