# Generated by Django 3.2.12 on 2024-08-06 15:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0013_booking'),
    ]

    operations = [
        migrations.AddField(
            model_name='booking',
            name='status',
            field=models.CharField(default='Pending', max_length=50),
        ),
    ]
