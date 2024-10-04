from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.hashers import check_password
from .models import Hospital

class HospitalBackend(BaseBackend):
    def authenticate(self, request, email=None, password=None, **kwargs):
        try:
            hospital = Hospital.objects.get(email=email)
            if hospital.check_password(password):
                return hospital
        except Hospital.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            return Hospital.objects.get(pk=user_id)
        except Hospital.DoesNotExist:
            return None
