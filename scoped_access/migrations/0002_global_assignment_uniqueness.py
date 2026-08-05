from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("scoped_access", "0001_initial"),
    ]

    operations = [
        migrations.AddConstraint(
            model_name="scopeassignment",
            constraint=models.UniqueConstraint(
                condition=(
                    ~models.Q(status="REVOKED")
                    & models.Q(level__isnull=False, scope_id__isnull=True)
                ),
                fields=("user", "role", "level"),
                name="scoped_access_unique_live_root",
            ),
        ),
        migrations.AddConstraint(
            model_name="scopeassignment",
            constraint=models.UniqueConstraint(
                condition=(
                    ~models.Q(status="REVOKED")
                    & models.Q(level__isnull=True, scope_id__isnull=True)
                ),
                fields=("user", "role"),
                name="scoped_access_unique_live_flat",
            ),
        ),
    ]
