# Generated by Django 5.1.4 on 2024-12-07 16:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('backendapis', '0008_offlinedata'),
    ]

    operations = [
        migrations.AlterField(
            model_name='offlinedata',
            name='end_time',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
