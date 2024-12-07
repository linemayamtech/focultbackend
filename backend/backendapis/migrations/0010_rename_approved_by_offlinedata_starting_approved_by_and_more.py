# Generated by Django 5.1.4 on 2024-12-07 16:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backendapis', '0009_alter_offlinedata_end_time'),
    ]

    operations = [
        migrations.RenameField(
            model_name='offlinedata',
            old_name='approved_by',
            new_name='starting_approved_by',
        ),
        migrations.AddField(
            model_name='offlinedata',
            name='ending_approved_by',
            field=models.CharField(max_length=50, null=True),
        ),
    ]
