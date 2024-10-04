from .serializers import *
from .models import *
import random
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import check_password
from django.utils import timezone
from django.core.mail import EmailMessage
from django.conf import settings
from django.views import View
from django.core.mail import send_mail, BadHeaderError
from django.contrib.auth.models import update_last_login
from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_GET
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth import authenticate,login,logout
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_protect
from django.db.models import Q
from django.db.models import Case, When, Value, IntegerField
from django.db.models import Count
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.urls import reverse
from django.contrib.auth.tokens import default_token_generator
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse, HttpResponseNotFound, HttpResponseBadRequest
from django.utils.http import urlsafe_base64_decode
from django.views.decorators.csrf import ensure_csrf_cookie
from django.contrib import messages
from django.utils.timezone import now
from django.contrib.auth.models import AnonymousUser

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import generics, status, permissions
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.generics import ListCreateAPIView
from rest_framework.filters import SearchFilter,OrderingFilter
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import viewsets, status
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import viewsets, mixins
from rest_framework_jwt.utils import jwt_decode_handler
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import status as http_status
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.pagination import PageNumberPagination
from rest_framework.generics import UpdateAPIView
from rest_framework import generics
from rest_framework.exceptions import NotFound


from .permissions import IsHospital,IsAdmin, IsPatient
from datetime import timedelta
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync


import json
import logging
import os
import datetime
import razorpay
import smtplib









client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token['username'] = user.username
        token['is_admin'] = user.is_superuser
        
        if hasattr(user, 'hospital'):
            token['hospital_id'] = user.hospital.id
            token['hospital_name'] = user.hospital.hospital_name

        return token

class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class=MyTokenObtainPairSerializer
    


@api_view(['GET'])
def getRoutes(request):

    routes=[
        'api/token',
        'api/token/refresh'
    ]

    return Response(routes)
class TestAuthenticationView(GenericAPIView):
    permission_classes = (IsAuthenticated)

    def get(self,request):
        data = {
            'msg':'its work'
        }
        return Response(data,status=status.HTTP_200_OK)

@api_view(['POST'])
def register_patient(request):
    if request.method == 'POST':
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()  # Save the user
            user.is_otp_verified = False  # Ensure OTP verification is set to False
            user.save()
            
            otp = random.randint(100000, 999999)  # Generate a random 6-digit OTP
            expires_at = timezone.now() + timezone.timedelta(minutes=10)  # OTP expires in 10 minutes
            OTP.objects.create(user=user, otp=otp, expires_at=expires_at)  # Store the OTP
            
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            
            # Send the OTP to the user's email
            send_otp_to_email(user.email, otp)  # Pass the OTP here
            
            return Response({
                'user': serializer.data,
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def send_otp_to_email(email, otp):
    try:
        send_mail(
           'Your OTP Code',
                f'Your OTP code is {otp}',
                'sumishasudha392@gmail.com',
                [email],
                fail_silently=False,
        )
    except Exception as e:
        print(e)
        
        
class GetPatientIDView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({'patient_id': user.id}, status=status.HTTP_200_OK)

# Utility to generate tokens manually for the user
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }    
    
class RegisterView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'User created successfully'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_patient_data(request):
    user = request.user  # The authenticated user
    if not user.is_patient:
        return Response({'detail': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)
    
    # Return patient-specific data
    return Response({
        'username': user.username,
        'email': user.email,
        # Include other patient-specific data
    })          
@api_view(['POST'])
@permission_classes([IsHospital])
def hospital_registration(request):
    if request.method == 'POST':
        serializer = HospitalRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)   




class HospitalAdditional(APIView):
    
    permission_classes=[IsHospital]
    

    def patch(self, request, hospitalEmail):
        try:
            instance = Hospital.objects.get(email=hospitalEmail)  # Query based on email
        except Hospital.DoesNotExist:
            return Response({'error': 'Hospital not found'}, status=status.HTTP_404_NOT_FOUND)

        # Pass the incoming data to the serializer with `partial=True` for partial updates
        serializer = HospitalAdditionalInfoSerializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#Login Part    
class HospitalLoginView(APIView):
    permission_classes=[IsHospital]
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        print(email,password)
        hospital = authenticate(request, email=email, password=password)
        print(hospital)

        if hospital is None:
            raise AuthenticationFailed('Invalid credentials')

        if not hospital.is_approved:
            return Response({'error': 'Account not approved'}, status=status.HTTP_403_FORBIDDEN)

        # Generate tokens using the hospital's tokens method
        tokens = hospital.tokens()

        return Response({
            'refresh': tokens['refresh'],
            'access': tokens['access'],
            'hospital_id': hospital.id,
        })

class HospitalAuthenticationView(APIView):
    permission_classes = [IsAuthenticated] 

    def get(self, request):
        auth = JWTAuthentication()
        validated_token = auth.get_validated_token(request.headers['Authorization'].split(' ')[1])
        user = auth.get_user(validated_token)
        print(f"Authenticated user: {user}")  # Logging the user for debug

        return Response({
            'email': user.email,
            'is_approved': user.is_approved
        }, status=status.HTTP_200_OK)
    


class AdminLoginView(APIView):
    permission_classes = [IsAdmin]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        # Authenticate using email and password
        user = authenticate(request, username=email, password=password)

        if user is not None and user.is_superuser:
            # Generate or retrieve token
            token, created = Token.objects.get_or_create(user=user)
            return Response({'token': token.key}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid credentials or not an admin'}, status=status.HTTP_401_UNAUTHORIZED)
    
class PatientLoginView(APIView):
    permission_classes = [IsPatient]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if email is None or password is None:
            return Response({'error': 'Please provide both email and password'}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(email=email, password=password)

        if not user:
            return Response({'error': 'Invalid Credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        
        if not user.is_otp_verified:
            return Response({'error': 'OTP verification is not completed'}, status=status.HTTP_403_FORBIDDEN)


        # Generate JWT tokens (access and refresh)
        refresh = RefreshToken.for_user(user)

        # Include user information in the response, no need to query separately later
        return Response({
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
            'user_id': user.id,
            'email': user.email,
            'name': user.username,  # Assuming you have a username field
        }, status=status.HTTP_200_OK)

#Otp 
        

        



    
class GenerateOTPView1(APIView):
    permission_classes = [IsPatient | IsHospital]

    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        user = User.objects.filter(email=email).first()
        hospital = Hospital.objects.filter(email=email).first()

        if not user and not hospital:
            return Response({"error": "User or Hospital not found"}, status=status.HTTP_400_BAD_REQUEST)
        
        otp = random.randint(100000, 999999)
        expires_at = timezone.now() + timezone.timedelta(minutes=10)

        if user:
            OTP.objects.create(user=user, otp=otp, expires_at=expires_at)
        elif hospital:
            HospitalOTP.objects.create(hospital=hospital, otp=otp, expires_at=expires_at)

        # Send email
        try:
            send_mail(
                'Your OTP Code',
                f'Your OTP code is {otp}',
                'sumishasudha392@gmail.com',
                [email],
                fail_silently=False,
            )
        except Exception as e:
            print(e)
            return Response({"error": "Failed to send email"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"message": "OTP sent to email"}, status=status.HTTP_200_OK)



class VerifyOTPView1(APIView):
    permission_classes = [IsPatient | IsHospital]

    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')

        if not email or not otp:
            return Response({"error": "Email and OTP are required"}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.filter(email=email).first()
        hospital = Hospital.objects.filter(email=email).first()

        otp_obj = None
        if user:
            otp_obj = OTP.objects.filter(user=user, otp=otp, expires_at__gte=timezone.now()).first()
        elif hospital:
            otp_obj = HospitalOTP.objects.filter(hospital=hospital, otp=otp, expires_at__gte=timezone.now()).first()

        if otp_obj:
            if user:
                user.is_otp_verified = True  # Mark user as OTP verified
                user.save()
            elif hospital:
                hospital.is_otp_verified = True  # Mark hospital as OTP verified
                hospital.save()

            otp_obj.delete()  # Delete OTP after successful verification
            return Response({"message": "OTP verified successfully"}, status=status.HTTP_200_OK)

        return Response({"error": "Invalid or expired OTP"}, status=status.HTTP_400_BAD_REQUEST)


    
#Hospital ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    

class DepartmentListView(APIView):
    permission_classes = [IsHospital] 
    def get(self, request, hospitalEmail):
        try:
            hospital = Hospital.objects.get(email=hospitalEmail)
        except Hospital.DoesNotExist:
            return Response({'error': 'Hospital not found'}, status=status.HTTP_404_NOT_FOUND)

        departments = Department.objects.filter(hospital=hospital)
        serializer = DepartmentSerializer(departments, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class DepartmentCreateView(APIView):
    permission_classes = [IsHospital] 
    def post(self, request, hospitalEmail):
        try:
            hospital = Hospital.objects.get(email=hospitalEmail)
        except Hospital.DoesNotExist:
            return Response({'error': 'Hospital not found'}, status=status.HTTP_404_NOT_FOUND)

        data = request.data.copy()
        data['hospital'] = hospital.id
        serializer = DepartmentSerializer(data=data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            print(serializer.errors)  # Print serializer errors
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class DepartmentEditView(APIView):
    permission_classes = [IsHospital] 
    def put(self, request, hospitalEmail, pk):
        try:
            hospital = Hospital.objects.get(email=hospitalEmail)
        except Hospital.DoesNotExist:
            return Response({'error': 'Hospital not found'}, status=status.HTTP_404_NOT_FOUND)

        try:
            department = Department.objects.get(hospital=hospital, pk=pk)
        except Department.DoesNotExist:
            return Response({'error': 'Department not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = DepartmentSerializer(department, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class DepartmentDeleteView(APIView):
    permission_classes = [IsHospital] 
    def delete(self, request, hospitalEmail, pk):
        try:
            hospital = Hospital.objects.get(email=hospitalEmail)
            department = Department.objects.get(id=pk, hospital=hospital)
            department.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Hospital.DoesNotExist:
            return Response({'error': 'Hospital not found'}, status=status.HTTP_404_NOT_FOUND)
        except Department.DoesNotExist:
            return Response({'error': 'Department not found'}, status=status.HTTP_404_NOT_FOUND)      
              
class DoctorListView(APIView):
    permission_classes = [IsHospital] 
    def get(self, request, hospitalEmail):
        
        try:
            hospital = Hospital.objects.get(email=hospitalEmail)
            
            # Filter departments that belong to the hospital
            departments = Department.objects.filter(hospital=hospital)
            
            # Filter doctors who belong to these departments
            doctors = Doctor.objects.filter(department__in=departments)
            
            # Serialize and return the data
            serializer = DoctorSerializer(doctors, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Hospital.DoesNotExist:
            return Response({'error': 'Hospital not found'}, status=status.HTTP_404_NOT_FOUND)


class DoctorCreateView(APIView):
    permission_classes = [IsHospital] 
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request, *args, **kwargs):
        data = request.data.copy()
        data['image'] = request.FILES.get('image')  # Handle file uploads

        # Ensure available_days is processed correctly
        if 'available_days' in request.data:
            data['available_days'] = request.data.get('available_days')

        serializer = DoctorSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class DoctorUpdateView(APIView):
    print("kkkkkkkkkkkkkkkkkkkkkkk")
    permission_classes = [IsHospital] 
    
    parser_classes = [MultiPartParser, FormParser]

    def get_object(self, doctor_id):
        try:
            return Doctor.objects.get(id=doctor_id)
        except Doctor.DoesNotExist:
            return None

    def put(self, request, doctor_id, *args, **kwargs):
        doctor = self.get_object(doctor_id)
        if not doctor:
            return Response({'error': 'Doctor not found'}, status=status.HTTP_404_NOT_FOUND)

        # Only update the image if a new file is provided
        data = request.data.copy()
        if 'image' not in data:
            data.pop('image', None)  # Remove the image field if not provided

        serializer = DoctorSerializer(doctor, data=data, partial=False)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



    def patch(self, request, doctor_id, *args, **kwargs):
        doctor = self.get_object(doctor_id)
        if not doctor:
            return Response({'error': 'Doctor not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = DoctorSerializer(doctor, data=request.data, partial=True)  # PATCH updates part of the object
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class DoctorDeleteView(APIView):
    permission_classes = [IsHospital] 

    def get_object(self, doctor_id):
        try:
            return Doctor.objects.get(id=doctor_id)
        except Doctor.DoesNotExist:
            return None

    def delete(self, request, doctor_id, *args, **kwargs):
        doctor = self.get_object(doctor_id)
        if not doctor:
            return Response({'error': 'Doctor not found'}, status=status.HTTP_404_NOT_FOUND)

        doctor.delete()
        return Response({'message': 'Doctor deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
          
 # we want to list the department for doctors which they are 
class HospitalDepartmentsView1(APIView):
    permission_classes = [IsHospital] 
    def get(self, request, hospitalEmail):
        try:
            hospital = Hospital.objects.get(email=hospitalEmail)
            departments = Department.objects.filter(hospital=hospital)
            serializer = DepartmentSerializer(departments, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Hospital.DoesNotExist:
            return Response({'error': 'Hospital not found'}, status=status.HTTP_404_NOT_FOUND)
        
class HospitalDetailView(APIView):
    permission_classes = [IsAdmin]  # Assuming only admins can view details
    
    def get(self, request, id):
        try:
            hospital = Hospital.objects.get(id=id)  # Fetch by id, not email
            serializer = HospitalSerializer(hospital)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Hospital.DoesNotExist:
            return Response({'error': 'Hospital not found'}, status=status.HTTP_404_NOT_FOUND)

class HospitalDetailView1(APIView):
    permission_classes = [IsHospital]  # Assuming only admins can view details

    def get(self, request, hospitalEmail):
        try:
            hospital = Hospital.objects.get(email=hospitalEmail)  # Fetch by email
            serializer = HospitalSerializer(hospital)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Hospital.DoesNotExist:
            return Response({'error': 'Hospital not found'}, status=status.HTTP_404_NOT_FOUND)

class HospitalUpdateView(UpdateAPIView):
    permission_classes = [IsHospital] 
    queryset = Hospital.objects.all()
    serializer_class = HospitalSerializer
    lookup_field = 'email'
    http_method_names = ['patch']

    def patch(self, request, *args, **kwargs):
        email = self.kwargs.get('email')
        try:
            hospital = Hospital.objects.get(email=email)
        except Hospital.DoesNotExist:
            return Response({'error': 'Hospital not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(hospital, data=request.data, partial=True)
        if serializer.is_valid():
            self.perform_update(serializer)
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class BookingPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'limit'
    max_page_size = 100
class HospitalBookingView(APIView):
    permission_classes = [IsHospital]

    def get(self, request, hospitalEmail):
        try:
            status_filter = request.query_params.get('status', '')

            # Base queryset
            bookings = Booking.objects.filter(hospital__email=hospitalEmail)
            
            # Apply status filter if provided
            if status_filter and status_filter != 'All':
                bookings = bookings.filter(status=status_filter)

            # Custom ordering logic:
            # Use Case and When to define custom sorting order
            status_order = {
                'Upcoming': 1,
                'Cancelled': 2,
                'Rejected': 3,
                'Completed': 4,
                'Refunded': 5,
            }

            # Annotate the queryset with a custom sorting value
            bookings = bookings.annotate(
                sort_order=Case(
                    *[When(status=status, then=Value(order)) for status, order in status_order.items()],
                    output_field=IntegerField()
                )
            ).order_by('sort_order', 'date')

            # Apply pagination
            paginator = BookingPagination()
            paginated_bookings = paginator.paginate_queryset(bookings, request)
            serializer = BookingSerializer(paginated_bookings, many=True)
            
            return paginator.get_paginated_response(serializer.data)
        except Exception as e:
            print("Error:", e)
            logger.error(f"Error fetching bookings for hospital email {hospitalEmail}: {e}")
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
@api_view(['PUT'])
@permission_classes([IsHospital])
def update_booking_status_hospital(request, id):
    try:
        booking = Booking.objects.get(id=id)
        new_status = request.data.get('status')
        doctor_name = request.data.get('doctor_name')  # Fetch doctor name from the request

        if new_status is None:
            return Response({"error": "Status is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Check for status transitions and handle accordingly
        if booking.status == 'Cancelled' and new_status not in ['Cancelled', 'Refunded']:
            return Response({"error": "Cannot change status from Cancelled to another status except Refunded."},
                            status=status.HTTP_400_BAD_REQUEST)
        
        if booking.status in ['Rejected', 'Completed'] and new_status in ['Upcoming', 'Cancelled']:
            return Response({"error": "Cannot revert status back to Upcoming or Cancelled once it is Rejected or Completed."},
                            status=status.HTTP_400_BAD_REQUEST)

        if new_status == 'Refunded' and booking.status in ['Cancelled', 'Rejected']:
            try:
                # Ensure doctor_name is available
                if not doctor_name:
                    doctor_name = booking.doctor.name  # Ensure doctor name fallback

                wallet, created = Wallet.objects.get_or_create(
                    patient=booking.patient,
                    hospital=booking.hospital,
                    defaults={
                        'doctor_name': doctor_name,  # Ensure doctor_name is saved
                        'appointment_fee': booking.appointment_fee,
                        'balance': 0.0
                    }
                )
                if not created:
                    wallet.balance += booking.appointment_fee
                    wallet.doctor_name = doctor_name  # Update doctor_name in case of change
                    wallet.save()
                else:
                    wallet.balance = booking.appointment_fee
                    wallet.save()
            except Exception as e:
                return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Update the booking status
        booking.status = new_status
        booking.save()

        return Response({"success": "Status updated successfully."}, status=status.HTTP_200_OK)

    except Booking.DoesNotExist:
        return Response({"error": "Booking not found."}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class CompletedBookingsListView(APIView):
    permission_classes = [IsHospital]
    
    def get(self, request, hospitalEmail):
        try:
           
            hospitalEmail = hospitalEmail.replace('%40', '@')
            bookings = Booking.objects.filter(hospital__email=hospitalEmail, status='Completed')
            if bookings.exists():
                serializer = BookingSerializer(bookings, many=True)
                return Response(serializer.data)
            else:
                return Response({"error": "No bookings found for this hospital email"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error fetching bookings for hospital email {hospitalEmail}: {e}")
            return Response({"error": "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

 
logger = logging.getLogger(__name__)

class Createpremiumorder(APIView):
    permission_classes = [IsHospital]

    @method_decorator(csrf_exempt)
    def post(self, request, *args, **kwargs):
        try:
            data = json.loads(request.body)
            logger.debug(f"Received data: {data}")

            # Validate data
            order_amount = data.get('amount')
            if order_amount is None:
                return JsonResponse({'error': 'Amount is required'}, status=400)
            if not isinstance(order_amount, int) or order_amount <= 0:
                return JsonResponse({'error': 'Invalid amount'}, status=400)

            order_currency = data.get('currency', 'INR')
            hospital_id = data.get('hospital_id')
            if not hospital_id:
                return JsonResponse({'error': 'Hospital ID is required'}, status=400)

            # Create Razorpay order
            order = client.order.create(dict(
                amount=order_amount,
                currency=order_currency,
                payment_capture='1'  # 1 for automatic capture, 0 for manual
            ))
            order_id = order['id']

            # Create or update PremiumHospital record
            hospital = Hospital.objects.get(id=hospital_id)
            premium_hospital, created = PremiumHospital.objects.get_or_create(
                hospital=hospital
            )
            if created:
                premium_hospital.premium_fee = order_amount / 100  # Convert paise to rupees
                premium_hospital.subscription_status = 'unpaid'
                premium_hospital.paid_date = None
            premium_hospital.save()

            # Return the order details
            return JsonResponse({
                'order_id': order_id,
                'amount': order_amount,
                'currency': order_currency,
                'booking_id': premium_hospital.id  # Use hospital ID or other booking identifier
            })

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        except Exception as e:
            logger.error(f"Error in Createpremiumorder: {e}")
            return JsonResponse({'error': str(e)}, status=400)
            

@csrf_exempt
@permission_classes([IsHospital])  
def razorpay_premium_success(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        try:
            # Validate the payment signature
            payment_id = data.get('razorpay_payment_id')
            order_id = data.get('razorpay_order_id')
            signature = data.get('razorpay_signature')
            
            # Verify payment signature
            client.utility.verify_payment_signature({
                'razorpay_order_id': order_id,
                'razorpay_payment_id': payment_id,
                'razorpay_signature': signature
            })

            # Update the PremiumHospital model
            booking_id = data.get('booking_id')
            PremiumHospital.objects.filter(id=booking_id).update(
                subscription_status='paid',
                paid_date=datetime.date.today()  # Update with actual paid date
            )

            return JsonResponse({'status': 'success'})

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({'error': 'Invalid method'}, status=405)
@api_view(['GET'])
@permission_classes([IsHospital])  
def check_subscription_status(request, hospital_id):
    try:
        hospital = Hospital.objects.get(id=hospital_id)
        premium_hospital = PremiumHospital.objects.filter(hospital=hospital).first()

        if premium_hospital and premium_hospital.subscription_status == 'paid':
            return JsonResponse({'isSubscribed': True})
        else:
            return JsonResponse({'isSubscribed': False})

    except Hospital.DoesNotExist:
        return JsonResponse({'error': 'Hospital not found'}, status=404)  

logger = logging.getLogger(__name__)

@csrf_exempt
@permission_classes([IsHospital])
def dashboard_data(request, email):
    email = email.strip().lower()  # Ensure email is clean and consistent
    logger.info(f"Received request for email: {email}")

    if request.method == 'GET':
        try:
            # Query Hospital model directly using email field
            hospital = Hospital.objects.get(email=email)
            logger.info(f"Hospital found: {hospital}")

            # You might need to adjust the query to get bookings based on your model's relationships
            bookings = Booking.objects.filter(hospital=hospital)  # Assuming Booking has a foreign key to Hospital
            bookings_count = bookings.count()

            patients_count = User.objects.filter(is_patient=True).count()
            growth = 15.2

            department_data = bookings.values('department__name').annotate(total_bookings=Count('id')).values('department__name', 'total_bookings')
            department_data_dict = {item['department__name']: item['total_bookings'] for item in department_data}

            response_data = {
                'bookings_count': bookings_count,
                'patients_count': patients_count,
                'growth': growth,
                'department_data': department_data_dict,
            }

            return JsonResponse(response_data)
        except Hospital.DoesNotExist:
            logger.error(f"Hospital not found: {email}")
            return JsonResponse({'error': 'Hospital not found'}, status=404)
        except Exception as e:
            logger.error(f"Exception occurred: {e}")
            return JsonResponse({'error': str(e)}, status=500)

    logger.error('Invalid request method')
    return JsonResponse({'error': 'Invalid request'}, status=400)
class HospitalDepartmentsView1(APIView):
    permission_classes = [IsHospital] 
    def get(self, request, hospitalEmail):
        try:
            hospital = Hospital.objects.get(email=hospitalEmail)
            departments = Department.objects.filter(hospital=hospital)
            serializer = DepartmentSerializer(departments, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Hospital.DoesNotExist:
            return Response({'error': 'Hospital not found'}, status=status.HTTP_404_NOT_FOUND)
        

class FeedbackDetailView(generics.GenericAPIView):
    permission_classes = [IsHospital]

    def get(self, request, hospitalEmail):
        try:
            # Filter feedbacks by the hospital's email
            feedbacks = Feedback.objects.filter(hospital__email=hospitalEmail)
            if not feedbacks.exists():
                return Response({'error': 'No feedback found for this hospital.'}, status=status.HTTP_404_NOT_FOUND)

            serializer = FeedbackSerializer(feedbacks, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Feedback.DoesNotExist:
            return Response({'error': 'Hospital not found'}, status=status.HTTP_404_NOT_FOUND)


# admin /////////////////////////////////////////////////////////////////////////////////////////////////////////



class HospitalRequestsView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request):
        hospitals = Hospital.objects.filter(is_approved=False)
        serializer = HospitalRegistrationSerializer(hospitals, many=True)
        return Response(serializer.data)

class ApproveHospitalView(APIView):
    permission_classes = [IsAdmin]

    def post(self, request, id):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            hospital = Hospital.objects.get(id=id)
            hospital.is_approved = True
            hospital.save()

            try:
                send_mail(
                    'Hospital Registration Approved',
                    'Congratulations! Your hospital registration has been approved.',
                    settings.EMAIL_HOST_USER,
                    [email],
                    fail_silently=False,
                )
            except BadHeaderError:
                return Response({'error': 'Invalid header found.'}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({'message': 'Hospital approved and notification sent successfully'}, status=status.HTTP_200_OK)
        except Hospital.DoesNotExist:
            return Response({'error': 'Hospital not found'}, status=status.HTTP_404_NOT_FOUND)


class RejectHospitalView(APIView):
    permission_classes = [IsAdmin]

    def post(self, request, id):
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            hospital = Hospital.objects.get(id=id)
            hospital.delete()  

            try:
                send_mail(
                    'Hospital Registration Rejected',
                    'We regret to inform you that your hospital registration has been rejected.',
                    settings.EMAIL_HOST_USER,
                    [email],
                    fail_silently=False,
                )
            except BadHeaderError:
                return Response({'error': 'Invalid header found.'}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return Response({'message': 'Hospital rejected and notification sent successfully'}, status=status.HTTP_200_OK)
        except Hospital.DoesNotExist:
            return Response({'error': 'Hospital not found'}, status=status.HTTP_404_NOT_FOUND)

        

class HospitalListView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request):
        hospitals = Hospital.objects.filter(is_approved=True)
        serializer = HospitalRegistrationSerializer(hospitals, many=True)
        return Response(serializer.data)
    
@api_view(['GET'])
@permission_classes([IsAuthenticated, IsAdmin])  # Allow only admin users to access this view
def get_patients(request):
    if request.method == 'GET':
        patients = User.objects.filter(is_superuser=False)
        serializer = UserRegistrationSerializer(patients, many=True)
        return Response(serializer.data)
    
class ToggleUserStatusView(APIView):
    permission_classes = [IsAdmin]
 
    def post(self, request, user_id):
        user = get_object_or_404(User, id=user_id)
        user.is_active = not user.is_active
        user.save()
        return Response({'status': 'success', 'is_active': user.is_active}, status=status.HTTP_200_OK)
    
class BlockUnblockHospitalView(APIView):
    permission_classes =[IsAdmin]
    def post(self, request, hospital_id):
        hospital = get_object_or_404(Hospital, id=hospital_id)
        action = request.data.get('action')

        if action == 'block':
            hospital.is_approved = False
            hospital.is_active = False
        elif action == 'unblock':
            hospital.is_approved = True
            hospital.is_active = True
        else:
            return Response({'error': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)

        hospital.save()
        return Response({'status': 'success', 'is_approved': hospital.is_approved}, status=status.HTTP_200_OK)


@csrf_exempt
@permission_classes([IsAdmin])
def get_blocked_patients(request):
   
    if request.method == 'GET':
        blocked_patients = User.objects.filter(is_active=False)
        print(blocked_patients)
        data = list(blocked_patients.values('id', 'username', 'email'))
        return JsonResponse(data, safe=False)
    return JsonResponse({'error': 'Invalid request method'}, status=400)


@csrf_exempt
def get_blocked_hospitals(request):
    if request.method == 'GET':
        blocked_hospitals = Hospital.objects.filter(is_active=False)
        data = list(blocked_hospitals.values('id', 'hospital_name', 'email', 'phone_number', 'address', 'district', 'photo'))
        return JsonResponse(data, safe=False)
    return JsonResponse({'error': 'Invalid request method'}, status=400)


class HospitalDepartmentsView(APIView):
    def get(self, request, id):
        try:
            hospital = Hospital.objects.get(id=id)
            print("jjjjjjjjjjjjjjjjjjjjj")
            departments = Department.objects.filter(hospital=hospital)
            serializer = DepartmentSerializer(departments, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Hospital.DoesNotExist:
            return Response({'error': 'Hospital not found'}, status=status.HTTP_404_NOT_FOUND)
        
class HospitalDoctorsView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request, id):
        try:
            # Retrieve the hospital
            hospital = Hospital.objects.get(id=id)

            # Retrieve departments associated with the hospital
            departments = Department.objects.filter(hospital=hospital)

            # Retrieve doctors associated with these departments
            doctors = Doctor.objects.filter(department__in=departments)
            
            # Serialize and return the data
            serializer = DoctorSerializer(doctors, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Hospital.DoesNotExist:
            return Response({'error': 'Hospital not found'}, status=status.HTTP_404_NOT_FOUND)
class PremiumHospitalsListView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request):
        # Filter hospitals with subscription status 'paid'
        hospitals = PremiumHospital.objects.filter(subscription_status='paid')
        
        # Serialize the filtered hospitals
        serializer = HospitalPremiumSerializer(hospitals, many=True)
        
        # Return the serialized data
        return Response(serializer.data)
    
class DashboardDataView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request):
        current_month = now().month
        current_year = now().year

        # Get number of hospitals
        total_hospitals = PremiumHospital.objects.count()

        # Get number of patients
        total_patients = User.objects.filter(is_patient=True).count()

        # Data for pie chart (Example: distribution of hospitals by subscription status)
        status_distribution = PremiumHospital.objects.values('subscription_status').annotate(count=Count('id'))

        # Data for learning curve
        # Adjusted query to use existing fields
        # Here, we assume `last_login` could be used to approximate registration for demonstration purposes
        learning_curve_data = User.objects.filter(
            last_login__year=current_year,
            last_login__month=current_month,
            is_patient=True
        ).values('last_login').annotate(count=Count('id')).order_by('last_login')

        return Response({
            'total_hospitals': total_hospitals,
            'total_patients': total_patients,
            'status_distribution': status_distribution,
            'learning_curve_data': list(learning_curve_data)
        })

# Patient  ////////////////////////////////////////////////////////////////////////////////////////////////////////

@permission_classes([IsPatient])  
def get_districts(request):
    print('Fetching approved districts...')
    # Fetch districts from approved hospitals
    districts = Hospital.objects.filter(is_approved=True).values_list('district', flat=True).distinct()
    return JsonResponse({'districts': list(districts)})

@permission_classes([IsPatient])  
def get_hospitals_by_district(request, district):
    hospitals = Hospital.objects.filter(district=district, is_approved=True).values('id', 'hospital_name')
    return JsonResponse({'hospitals': list(hospitals)})

class HospitalDepartmentsView(APIView):
    permission_classes =[IsPatient]
    def get(self, request, id):
        try:
            hospital = Hospital.objects.get(id=id)
            print("jjjjjjjjjjjjjjjjjjjjj")
            departments = Department.objects.filter(hospital=hospital)
            serializer = DepartmentSerializer(departments, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Hospital.DoesNotExist:
            return Response({'error': 'Hospital not found'}, status=status.HTTP_404_NOT_FOUND)
            

class HospitalDoctors(APIView):
     permission_classes =[IsPatient]
     def get(self, request, id):
        try:
            department = Department.objects.get(id=id)
            print("jjjjjjjjjjjjjjjjjjjjj")
            doctors = Doctor.objects.filter(department=department)
            serializer = DoctorSerializer(doctors, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Hospital.DoesNotExist:
            return Response({'error': 'Hospital not found'}, status=status.HTTP_404_NOT_FOUND)

class DoctorAvailable(APIView):
    permission_classes =[IsPatient]
    def get(self,request,id):
        try:
            doctor = Doctor.objects.get(id=id)
            available_days = doctor.available_days
            print("jjjjjjjjjjjjjjjjjjjjj")
            print(available_days)
            return Response(available_days)
        except Doctor.DoesNotExist:
            return Response({'error': 'Doctor not found'}, status=404)
        

@require_GET
@permission_classes([IsPatient])  
def get_patient_id(request):
    email = request.GET.get('email')
    if not email:
        return JsonResponse({'error': 'Email parameter is required'}, status=400)
    
    try:
        patient = User.objects.get(email=email)
        return JsonResponse({'patient_id': patient.id})
    except User.DoesNotExist:
        return JsonResponse({'error': 'Patient not found'}, status=404)
    
logger = logging.getLogger(__name__)
@csrf_exempt  # Ideally, you'd handle CSRF properly if needed
@api_view(['POST'])  # Use DRF's @api_view to integrate with DRF's request/response cycle
@permission_classes([IsAuthenticated, IsPatient])  # Enforces user authentication
def create_razorpay_order(request):
    try:
        data = request.data  # DRF provides request.data for POSTed data
        hospital_id = data.get('hospital_id')
        department_id = data.get('department_id')
        doctor_id = data.get('doctor_id')
        date = data.get('date')

        # Get the authenticated user (patient)
        user = request.user  # DRF handles the authentication, no need to check AnonymousUser

        # Proceed with Razorpay order creation
        amount = 1000 * 100  # Example amount in paise
        currency = 'INR'
        receipt = f'order_rcptid_{user.id}'  # Use user ID for receipt

        order = client.order.create({
            'amount': amount,
            'currency': currency,
            'receipt': receipt,
            'payment_capture': '1'
        })

        # Fetch hospital, department, and doctor objects
        hospital = Hospital.objects.get(id=hospital_id)
        department = Department.objects.get(id=department_id)
        doctor = Doctor.objects.get(id=doctor_id)

        # Check if the doctor has reached the token limit
        existing_bookings = Booking.objects.filter(
            hospital=hospital,
            department=department,
            doctor=doctor,
            date=date
        )

        if existing_bookings.count() >= 20:
            return JsonResponse({
                'status': 'failed',
                'message': 'Token limit reached. No more bookings available for this doctor today.'
            }, status=400)

        # Create the new booking for the authenticated patient
        token_number = existing_bookings.count() + 1
        booking = Booking.objects.create(
            patient=user,  # Use the authenticated user as the patient
            hospital=hospital,
            department=department,
            doctor=doctor,
            date=date,
            token_number=token_number
        )

        # Notify hospital about new booking
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            f'notification_{hospital_id}',
            {
                'type': 'send_notification',
                'message': f'New booking created! Token number: {booking.token_number}'
            }
        )

        return JsonResponse({
            'order_id': order['id'],
            'amount': amount,
            'currency': currency,
            'booking_id': booking.id,
            'token_number': booking.token_number
        }, status=201)

    except json.JSONDecodeError:
        return JsonResponse({'status': 'failed', 'message': 'Invalid JSON format'}, status=400)
    except Hospital.DoesNotExist:
        return JsonResponse({'status': 'failed', 'message': 'Invalid hospital ID'}, status=400)
    except Department.DoesNotExist:
        return JsonResponse({'status': 'failed', 'message': 'Invalid department ID'}, status=400)
    except Doctor.DoesNotExist:
        return JsonResponse({'status': 'failed', 'message': 'Invalid doctor ID'}, status=400)
    except Exception as e:
        logger.error(f"Error creating booking: {str(e)}")
        return JsonResponse({'status': 'failed', 'message': f'Error: {str(e)}'}, status=500)

@csrf_exempt
@api_view(['POST']) 
@permission_classes([IsAuthenticated, IsPatient])
def razorpay_payment_success(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            razorpay_payment_id = data.get('razorpay_payment_id')
            razorpay_order_id = data.get('razorpay_order_id')
            razorpay_signature = data.get('razorpay_signature')

            # Verify payment
            client.utility.verify_payment_signature({
                'razorpay_order_id': razorpay_order_id,
                'razorpay_payment_id': razorpay_payment_id,
                'razorpay_signature': razorpay_signature,
            })

            # Retrieve the authenticated user (patient)
            user = request.user

            # Retrieve booking for the authenticated patient
            booking = Booking.objects.filter(patient=user).last()  # Fetch the latest booking for the patient

            if not booking:
                return JsonResponse({'status': 'failed', 'message': 'Booking not found for the authenticated user.'}, status=404)

            # Update booking status
            booking.payment_status = 'PAID'
            booking.save()

            # Notify hospital in real-time
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f'notification_{booking.hospital.id}',
                {
                    'type': 'send_notification',
                    'message': f'Payment confirmed for booking {booking.id}. Token number: {booking.token_number}'
                }
            )

            return JsonResponse({'status': 'success', 'message': 'Payment verified and booking confirmed.'})
        except Exception as e:
            logger.error(f"Payment verification failed: {str(e)}")
            return JsonResponse({'status': 'failed', 'message': str(e)}, status=400)

        
class BookingListByPatient(APIView):
    permission_classes = [IsAuthenticated, IsPatient]  # Ensure only authenticated patients can access this

    def get(self, request):
        try:
            # Get the authenticated user
            user = request.user  # This will give you the authenticated User instance

            # Fetch bookings where the patient is the authenticated user
            bookings = Booking.objects.filter(patient=user)  # Assuming patient is a ForeignKey to User model

            if bookings.exists():
                serializer = BookingSerializer(bookings, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)

            return Response({'error': 'No bookings found'}, status=status.HTTP_404_NOT_FOUND)

        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)        


@api_view(['PUT'])
@permission_classes([IsAuthenticated, IsPatient])  # Only authenticated patients can access this
def update_booking_status(request, booking_id):
    try:
        # Get the authenticated user
        user = request.user  # This will give you the authenticated patient

        # Fetch the booking by ID
        booking = Booking.objects.get(id=booking_id)

        # Ensure that only the patient who created the booking can cancel it
        if booking.patient != user:  # Compare authenticated user with booking's patient
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)

        # Get the new status from the request data
        new_status = request.data.get('status')

        # Check if the new status is valid
        if new_status in dict(Booking.STATUS_CHOICES):  # Ensure status is a valid choice
            booking.status = new_status
            booking.save()
            return Response({'message': 'Booking status updated successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid status'}, status=status.HTTP_400_BAD_REQUEST)

    except Booking.DoesNotExist:
        return Response({'error': 'Booking not found'}, status=status.HTTP_404_NOT_FOUND)

    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['GET'])
@permission_classes([IsPatient])  
def get_patient_wallets(request, patient_id):
    try:
        patient = User.objects.get(id=patient_id)
        wallets = Wallet.objects.filter(patient=patient)
        wallets_data = [
            {
                "hospital": wallet.hospital.hospital_name,
                "doctor_name": wallet.doctor_name,
                "appointment_fee": wallet.appointment_fee,
                "transaction_date": wallet.transaction_date,
                "balance": wallet.balance,
            }
            for wallet in wallets
        ]
        return Response(wallets_data, status=status.HTTP_200_OK)
    except User.DoesNotExist:
        return Response({"error": "Patient not found."}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)    
    

@api_view(['GET'])
@permission_classes([IsPatient])
def booking_notifications(request):
    patient_id = request.GET.get('patient_id')
    try:
        bookings = Booking.objects.filter(patient_id=patient_id).order_by('-date')
        serializer = BookingSerializer(bookings, many=True)
        return JsonResponse(serializer.data, safe=False)
    except Booking.DoesNotExist:
        return JsonResponse({'error': 'No bookings found for this patient'}, status=404)
    
@api_view(['POST'])
@permission_classes([IsPatient])
def wallet_payment(request):
    patient_id = request.data.get('patient_id')
    hospital_id = request.data.get('hospital_id')
    department_id = request.data.get('department_id')
    doctor_id = request.data.get('doctor_id')
    date = request.data.get('date')

    try:
        patient = User.objects.get(id=patient_id)
        hospital = Hospital.objects.get(id=hospital_id)
        department = Department.objects.get(id=department_id)
        doctor = Doctor.objects.get(id=doctor_id)

        # Fetch or create the wallet for the patient
        wallet, created = Wallet.objects.get_or_create(patient=patient, hospital=hospital)

        # Check if the patient has sufficient balance
        if wallet.balance >= hospital.appointment_limit:
            # Deduct the appointment fee from the wallet
            wallet.withdraw(hospital.appointment_limit)

            # Generate token number by counting the existing bookings for the same date and hospital
            token_number = Booking.objects.filter(hospital=hospital, date=date).count() + 1

            # Create the booking
            booking = Booking(
                patient=patient,
                hospital=hospital,
                department=department,
                doctor=doctor,
                date=date,
                payment_method='wallet',
                appointment_fee=hospital.appointment_limit,
                token_number=token_number  # Set the token number
            )
            booking.save()

            return JsonResponse({'success': True, 'booking_id': booking.token_number})
        else:
            return JsonResponse({'success': False, 'message': 'Insufficient wallet balance'})

    except Wallet.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Wallet does not exist'})

    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)})

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated,IsPatient]  # Ensure this permission class checks authentication

    def get(self, request):
        user = request.user  # This will give you the authenticated User instance
        serializer = UserSerializer(user)
        return Response(serializer.data)

    def patch(self, request):
        user = request.user  # This will give you the authenticated User instance
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
@ensure_csrf_cookie  
def get_csrf_token(request):
    return JsonResponse({'message': 'CSRF token set'})  

def generate_otp():
    return str(random.randint(100000, 999999))

@csrf_exempt
def forgot_password(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')

            if not email:
                return JsonResponse({'error': 'Email is required'}, status=400)

            try:
                customer = User.objects.get(email=email)
            except User.DoesNotExist:
                return JsonResponse({'error': 'User with this email does not exist'}, status=404)

            otp = generate_otp()

            # Create OTP record in the database
            expiration_time = timezone.now() + timedelta(minutes=10)  # OTP expires in 10 minutes
            OTP.objects.create(user=customer, otp=otp, expires_at=expiration_time)

            sender_email = "sumishasudha392@gmail.com"
            email_subject = 'Your OTP for Password Reset'
            email_body = f"Your OTP is: {otp}"

            try:
                send_mail(
                    email_subject,
                    email_body,
                    sender_email,
                    [email],
                    fail_silently=False,
                )
            except Exception as e:
                return JsonResponse({'error': f'Failed to send email. {str(e)}'}, status=500)

            return JsonResponse({'message': 'OTP has been sent to your email.'}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format'}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=400)

@csrf_exempt
def reset_password(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            entered_otp = data.get('otp')
            new_password = data.get('new_password')
            confirm_password = data.get('confirm_password')

            if new_password != confirm_password:
                return JsonResponse({'error': 'Passwords do not match'}, status=400)

            # Validate the OTP
            try:
                otp_record = OTP.objects.get(otp=entered_otp, expires_at__gte=timezone.now())
            except OTP.DoesNotExist:
                return JsonResponse({'error': 'Invalid or expired OTP'}, status=400)

            # Get the user associated with the OTP
            customer = otp_record.user

            # Set the new password for the user
            customer.set_password(new_password)
            customer.save()

            # Delete the OTP record after successful password reset
            otp_record.delete()

            return JsonResponse({'message': 'Password reset successful. Please login with your new password.'}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format'}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=400)



class SubmitFeedbackView(APIView):
    permission_classes = [IsPatient]  
    def post(self, request, *args, **kwargs):
        user_email = request.data.get('user_email')
        hospital_id = request.data.get('hospital_id')
        print(hospital_id,"'''''''''''''")
        message = request.data.get('message')
        
        try:
            user = User.objects.get(email=user_email)
            hospital = Hospital.objects.get(id=hospital_id)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        except Hospital.DoesNotExist:
            return Response({"error": "Hospital not found"}, status=status.HTTP_404_NOT_FOUND)
        
        feedback = Feedback(user=user, hospital=hospital, message=message)
        feedback.save()
        
        return Response({"message": "Feedback submitted successfully"}, status=status.HTTP_201_CREATED)
    
def get_booking_details(request, booking_id):
    permission_classes = [IsPatient]  
    try:
        # Fetch the booking details by ID
        booking = Booking.objects.get(id=booking_id)
        
        # Extract relevant data for serialization
        booking_data = {
            'id': booking.id,
            'date': booking.date,
            'hospital_id': booking.hospital.id,  # Hospital ID
            'hospital_email': booking.hospital.email,  # Hospital email
        }
        
        return JsonResponse(booking_data)
    except Booking.DoesNotExist:
        return HttpResponseNotFound('Booking not found')
    
