# Generated by Django 3.2.12 on 2024-07-19 18:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0005_auto_20240715_1855'),
    ]

    operations = [
        migrations.AlterField(
            model_name='department',
            name='name',
            field=models.CharField(max_length=100, unique=True),
        ),
    ]
