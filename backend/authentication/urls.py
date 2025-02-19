from django.urls import path
from .views import RegistrationView, LoginView, LogoutView, UserListView, UserDeleteView, MFAVerifyView
from rest_framework_simplejwt.views import TokenRefreshView
from drf_totp.views import GenerateOTP as GenerateTOTPSecretView, VerifyOTP as TOTPVerifyView, OTPStatus as TOTPStatusView, DisableOTP as TOTPDisableView, ValidateOTP as TOTPValidateView

urlpatterns = [
    path('register/', RegistrationView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    path('mfa/setup/', GenerateTOTPSecretView.as_view(), name='mfa-setup'),
    path('mfa/verify/', MFAVerifyView.as_view(), name='mfa-verify'),
    path('mfa/status/', TOTPStatusView.as_view(), name='mfa-status'),
    path('mfa/disable/', TOTPDisableView.as_view(), name='mfa-disable'),
    path('mfa/validate/', TOTPValidateView.as_view(), name='mfa-validate'),

    path('admin/users/', UserListView.as_view(), name='admin-users'),
    path('admin/user/<int:user_id>/', UserDeleteView.as_view(), name='admin-user-delete'),
]