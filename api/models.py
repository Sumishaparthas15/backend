from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager,Group, Permission
from django.contrib.auth.hashers import make_password
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.contrib.postgres.fields import JSONField

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=250, unique=True)
    email = models.CharField(max_length=250, unique=True)
    profile_img = models.ImageField(upload_to='profile', blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False) 
    is_patient = models.BooleanField(default=False)
    is_otp_verified = models.BooleanField(default=False)

    groups = models.ManyToManyField(Group, related_name='user_groups', blank=True)
    user_permissions = models.ManyToManyField(Permission, related_name='user_permissions', blank=True)
    

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = CustomUserManager()

    def __str__(self):
        return self.email
    class Meta:
        db_table = 'api_user'
        managed = True
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
User = get_user_model()
class Hospital(AbstractBaseUser, PermissionsMixin):
    hospital_name = models.CharField(max_length=255, unique=True)
    email = models.CharField(max_length=250, unique=True)
    phone_number = models.CharField(max_length=20)
    address = models.TextField()
    city = models.CharField(max_length=100)
    district = models.CharField(max_length=100)
    pin_code = models.CharField(max_length=10)
    photo = models.ImageField(upload_to='hospital_photos/')
    is_approved = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    ownership_details = models.TextField(default='Hospital ownership details') 
    owner_photo = models.ImageField(upload_to='owner_photos/', default='default_owner_photo.jpg') 
    license_number = models.CharField(max_length=100, default='0000')
    license_expiry_date = models.DateField(default=timezone.now) 
    accreditations = models.CharField(max_length=255, default='') 
    acc_certification = models.FileField(upload_to='acc_certifications/', null=True, blank=True)
    admin_contact_person = models.CharField(max_length=255, default='Unknown')
    admin_contact_phone = models.CharField(max_length=20, default='')
    appointment_limit = models.IntegerField(default=1000) 

    groups = models.ManyToManyField(Group, related_name='hospital_groups', blank=True)
    user_permissions = models.ManyToManyField(Permission, related_name='hospital_permissions', blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['hospital_name']

    objects = CustomUserManager()

    class Meta:
        db_table = 'api_hospital'
        managed = True
        verbose_name = 'Hospital'
        verbose_name_plural = 'Hospitals'


    def tokens(self):
        refresh = RefreshToken()
        access_token = refresh.access_token
        return {
            'refresh': str(refresh),
            'access': str(access_token),
        }
    def _str_(self):
        return self.hospital_name
    

    
class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

class HospitalOTP(models.Model):
    hospital = models.ForeignKey(Hospital, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()    
    
        
class Department(models.Model):
    name = models.CharField(max_length=100)
    image = models.ImageField(upload_to='department_images/')
    hospital = models.ForeignKey(Hospital, on_delete=models.CASCADE, related_name='departments')

    class Meta:
        db_table = 'api_department'
        managed = True
        verbose_name = 'Department'
        verbose_name_plural = 'Departments'

    def __str__(self):
        return self.name
    

class Doctor(models.Model):
    SEX_CHOICES = [
        ('Male', 'Male'),
        ('Female', 'Female'),
        ('Other', 'Other'),
    ]

    department = models.ForeignKey(Department, on_delete=models.CASCADE, related_name='doctors')
    name = models.CharField(max_length=100)
    age = models.PositiveIntegerField()
    sex = models.CharField(max_length=10, choices=SEX_CHOICES)
    image = models.ImageField(upload_to='doctor_images/')
    experience = models.PositiveIntegerField()
    op_time = models.CharField(max_length=20)
    available_days = models.JSONField()
   
   

    class Meta:
        db_table = 'api_doctor'
        managed = True
        verbose_name = 'Doctor'
        verbose_name_plural = 'Doctors'

    def __str__(self):
        return self.name    

class Booking(models.Model):
    STATUS_CHOICES = [
        ('Upcoming', 'Upcoming'),
        ('Cancelled', 'Cancelled'),
        ('Rejected', 'Rejected'),
        ('Refunded', 'Refunded'),
        ('Completed', 'Completed'),
    ]
    PAYMENT_METHOD_CHOICES = [
        ('razorpay', 'Razorpay'),
        ('wallet', 'Wallet'),
    ]
    patient = models.ForeignKey(User, on_delete=models.CASCADE)
    hospital = models.ForeignKey(Hospital, on_delete=models.CASCADE)    
    department = models.ForeignKey(Department, on_delete=models.CASCADE)
    doctor = models.ForeignKey(Doctor, on_delete=models.CASCADE)
    date = models.DateField()
    token_number = models.PositiveIntegerField()
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='Upcoming')
    appointment_fee = models.DecimalField(max_digits=10, decimal_places=2, editable=False, default=0.00) 
    payment_method = models.CharField(max_length=10, choices=PAYMENT_METHOD_CHOICES, default='razorpay')

    class Meta:
        unique_together = ('hospital', 'date', 'token_number')

    def save(self, *args, **kwargs):
        # Set appointment fee based on the hospital's settings
        if not self.appointment_fee:
            self.appointment_fee = self.hospital.appointment_limit

        # Handle wallet payment
        if self.payment_method == 'wallet':
            try:
                wallet = Wallet.objects.get(patient=self.patient, hospital=self.hospital)
                if wallet.balance >= self.appointment_fee:
                    wallet.balance -= self.appointment_fee
                    wallet.save()
                else:
                    raise ValueError("Insufficient wallet balance")
            except Wallet.DoesNotExist:
                raise ValueError("Wallet not found for this patient and hospital")

        super().save(*args, **kwargs)


class Wallet(models.Model):
    patient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='wallets')
    hospital = models.ForeignKey('Hospital', on_delete=models.CASCADE, related_name='hospital_wallets')
    doctor_name = models.CharField(max_length=255)
    appointment_fee = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
    transaction_date = models.DateField(default=timezone.now)
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)

    def __str__(self):
        return f"Wallet for {self.patient.username} - Balance: {self.balance}"

    def deposit(self, amount):
        self.balance += amount
        self.save()

    def withdraw(self, amount):
        if amount <= self.balance:
            self.balance -= amount
            self.save()
            return True
        return False        
    
class PremiumHospital(models.Model):
    hospital = models.ForeignKey(Hospital, on_delete=models.CASCADE, related_name='premium_details')
    subscription_status = models.CharField(max_length=50, choices=[('paid', 'Paid'), ('unpaid', 'Unpaid')], default='unpaid')
    premium_fee = models.DecimalField(max_digits=10, decimal_places=2, editable=False, default=0.00) 
    paid_date = models.DateField(null=True, blank=True)
    
    class Meta:
        db_table = 'api_premium_hospital'
        managed = True
        verbose_name = 'Premium Hospital'
        verbose_name_plural = 'Premium Hospitals'

    def __str__(self):
        return f'{self.hospital.hospital_name} - {self.subscription_status}'
class Feedback(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    hospital = models.ForeignKey(Hospital, on_delete=models.CASCADE)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'Feedback from {self.user.email} at {self.hospital.name}'