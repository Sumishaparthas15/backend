# Generated by Django 3.2.12 on 2024-09-04 15:25

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0025_booking_payment_method'),
    ]

    operations = [
        migrations.CreateModel(
            name='PremiumHospital',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('subscription_status', models.CharField(choices=[('paid', 'Paid'), ('unpaid', 'Unpaid')], default='unpaid', max_length=50)),
                ('premium_fee', models.DecimalField(decimal_places=2, default=0.0, editable=False, max_digits=10)),
                ('paid_date', models.DateField(blank=True, null=True)),
                ('hospital', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='premium_details', to='api.hospital')),
            ],
            options={
                'verbose_name': 'Premium Hospital',
                'verbose_name_plural': 'Premium Hospitals',
                'db_table': 'api_premium_hospital',
                'managed': True,
            },
        ),
    ]
