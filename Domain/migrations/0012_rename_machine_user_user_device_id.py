from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Domain', '0011_electoral_college_email_sent'),
    ]

    operations = [
        migrations.RenameField(
            model_name='user',
            old_name='machine_user',
            new_name='device_id',
        ),
        migrations.AlterField(
            model_name='user',
            name='device_id',
            field=models.CharField(blank=True, db_index=True, help_text='Unique, OS-agnostic identifier of the physical device or machine', max_length=64, null=True, verbose_name='device id'),
        ),
    ]
