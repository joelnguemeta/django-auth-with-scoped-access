import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("scoped_access", "0002_global_assignment_uniqueness"),
    ]

    operations = [
        migrations.AlterField(
            model_name="scopeassignment",
            name="user",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.PROTECT,
                related_name="scoped_assignments",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
