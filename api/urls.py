from django.urls import path
from . import views
from .views import *
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    
    path('',views.getRoutes),
    path('token/',MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('get-csrf-token/', views.get_csrf_token), 


        path('generate-otp1/', GenerateOTPView1.as_view(), name='generate_otp'),
        path('verify-otp1/', VerifyOTPView1.as_view(), name='verify_otp'),

    #hospital
   
    path('hossignup/', views.hospital_registration, name='hospital-registration'),
    path('HospitalAdditional/<str:hospitalEmail>/', HospitalAdditional.as_view(), name='hospital-additional'),
    path('hospital_login/', HospitalLoginView.as_view(), name='hospital_login'),
    path('hospital_authentication/', HospitalAuthenticationView.as_view(), name='hospital_authentication'),

    path('departments/<str:hospitalEmail>/', DepartmentListView.as_view(), name='department-list'),
    # path('departments/<str:hospitalEmail>/create/', DepartmentCreateView.as_view(), name='department-create'),
    path('departments/<str:hospitalEmail>/create/', DepartmentCreateView.as_view(), name='department-create'),
    path('departments/<str:hospitalEmail>/<int:pk>/edit/', DepartmentEditView.as_view(), name='department-edit'),
    path('departments/<str:hospitalEmail>/<int:pk>/delete/', DepartmentDeleteView.as_view(), name='department-delete'),
    path('hospital_profile/<str:hospitalEmail>/', HospitalDetailView1.as_view(), name='hospital-detail'),

    path('hospital_profile_update/<str:email>/', HospitalUpdateView.as_view(), name='hospital-update'),
    path('hospitaldepartments/<str:hospitalEmail>/', HospitalDepartmentsView1.as_view(), name='hospital_departments'),
    path('doctors/<str:hospitalEmail>/', DoctorListView.as_view(), name='doctor-list'),
    path('doctors/<str:hospital_email>/add/', DoctorCreateView.as_view(), name='doctor-create'),
    path('doctors/<int:doctor_id>/update/', DoctorUpdateView.as_view(), name='doctor-update'), 
    path('doctors/<int:doctor_id>/delete/', DoctorDeleteView.as_view(), name='doctor-delete'), 
    path('hospital_bookings/<str:hospitalEmail>/', HospitalBookingView.as_view(), name='hospital_bookings'),
    path('update_booking_status_hospital/<int:id>/', update_booking_status_hospital, name='update-booking-status-hospital'),
    path('completed_bookings/<str:hospitalEmail>/', CompletedBookingsListView.as_view(), name='completed_bookings'),
    path('dashboard/<str:email>/', views.dashboard_data, name='dashboard_data'),
     path('check-subscription-status/<int:hospital_id>/', check_subscription_status, name='check_subscription_status'),

    #admin
    path('admin_login/', AdminLoginView.as_view()),
    path('hospital_requests/', HospitalRequestsView.as_view(), name='hospital_requests'),
    path('approve_hospital/<int:id>/', ApproveHospitalView.as_view(), name='approve_hospital'),
    path('reject_hospital/<int:id>/', RejectHospitalView.as_view(), name='approve_hospital'),
    path('HospitalListView/', HospitalListView.as_view(), name='HospitalListView'),
    path('get_patients/',views.get_patients,name='get_patients'),
    path('toggle_user_status/<int:user_id>/', ToggleUserStatusView.as_view(), name='toggle_user_status'),
    path('block_unblock_hospital/<int:hospital_id>/', BlockUnblockHospitalView.as_view(), name='block_unblock_hospital'),
    path('get_blocked_patients/', get_blocked_patients, name='get_blocked_patients'),
    path('get_blocked_hospitals/', get_blocked_hospitals, name='get_blocked_hospitals'),
    path('hospital/<int:id>/', HospitalDetailView.as_view(), name='hospital-detail'),
    path('hospitaldepartments1/<int:id>/', HospitalDepartmentsView.as_view(), name='hospital_departments'),
    path('hospitaldoctors1/<int:id>/', HospitalDoctorsView.as_view(), name='hospital_doctors'),
    path('create-premium-order/', Createpremiumorder.as_view(), name='create_premium_order'),
    path('razorpay-premium-success/', views.razorpay_premium_success, name='razorpay_premium_success'),
   
    path('premium_hospitals/', PremiumHospitalsListView.as_view(), name='premium_hospitals_list'),
    path('dashboard-data/', DashboardDataView.as_view(), name='dashboard-data'),


    #patients

    path('register/', views.register_patient, name='register_patient'),
    path('patient_login/',PatientLoginView.as_view()),
    path('districts/', views.get_districts, name='get_districts'),
    path('hospitals/<str:district>/', views.get_hospitals_by_district, name='get_hospitals_by_district'),
    path('hospitaldepartments1/<int:id>/', HospitalDepartmentsView.as_view(), name='hospital_departments'),
    path('hospitaldoctors/<int:id>/', HospitalDoctors.as_view(), name='hospitaldoctors'),
    path('doctoravailable/<int:id>/', DoctorAvailable.as_view(), name='doctoravailable'),
    path('get_patient_id/', views.get_patient_id, name='get_patient_id'),
    path('bookings/', BookingListByPatient.as_view(), name='booking-list-by-patient'),
    path('patient_wallets/<int:patient_id>/', views.get_patient_wallets, name='get_patient_wallets'),
    path('create-razorpay-order/', views.create_razorpay_order, name='create_razorpay_order'),
    path('razorpay-payment-success/', views.razorpay_payment_success, name='razorpay_payment_success'),

    path('update_booking_status/<int:booking_id>/', views.update_booking_status, name='update_booking_status'),
    path('notifications/', views.booking_notifications, name='booking-notifications'),
    path('wallet_payment/', views.wallet_payment, name='booking-wallet_payment'),
    path('Patientsprofile/', UserProfileView.as_view(), name='user-profile'),

    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('reset-password/', views.reset_password, name='password_reset_confirm'),
    path('submit_feedback/', SubmitFeedbackView.as_view(), name='submit_feedback'),
    path('get_booking_details/<int:booking_id>/', get_booking_details, name='get_booking_details'),
    path('feedback-detail/<str:hospitalEmail>/', views.FeedbackDetailView.as_view(), name='feedback-detail'),
    path('profile/',TestAuthenticationView.as_view()),
    

  



]    