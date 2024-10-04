# Generated by Django 3.2.12 on 2024-07-29 18:58

import django.contrib.postgres.fields.jsonb
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0011_remove_doctor_days'),
    ]

    operations = [
        migrations.AddField(
            model_name='doctor',
            name='available_days',
            field=django.contrib.postgres.fields.jsonb.JSONField(default=dict),
        ),
    ]
