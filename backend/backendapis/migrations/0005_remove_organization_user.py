# Generated by Django 5.1.4 on 2024-12-06 10:00

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('backendapis', '0004_organization_user'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='organization',
            name='user',
        ),
    ]
