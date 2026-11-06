from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("gear", "0001_initial")]

    operations = [
        migrations.AddField(model_name="pledge", name="is_member", field=models.BooleanField(default=False)),
    ]
