# Generated by Django 3.2.12 on 2024-07-21 13:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0006_alter_department_name'),
    ]

    operations = [
        migrations.AddField(
            model_name='hospital',
            name='is_active',
            field=models.BooleanField(default=True),
        ),
    ]
