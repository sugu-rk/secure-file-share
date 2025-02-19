from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import RegistrationSerializer, LoginSerializer, UserListSerializer, MFAVerifySerializer
from rest_framework_simplejwt.tokens import RefreshToken
from files.utils import log_audit_event
from rest_framework import serializers, status
from files.models import FailedLoginAttempt, AuditLog
from django.utils import timezone
import datetime
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from authentication.models import UserProfile
from drf_totp.models import TOTPAuth
import pyotp
from django.conf import settings
from django.http import HttpResponse
from rest_framework.permissions import AllowAny
from django.db import transaction


User = get_user_model()
TOTP_ISSUER_NAME = getattr(settings, "TOTP_ISSUER_NAME", "YourAppName")

FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW_MINUTES = 5

class RegistrationView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = [] # Disable authentication for this view
    def post(self, request):
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            log_audit_event(
                user=user,
                action_type='user_register',
                details=f"New user registered with email: {user.email}.",
                ip_address=request.META.get('REMOTE_ADDR')
            )
            refresh = RefreshToken.for_user(user)
            response = Response({
                'access': str(refresh.access_token),
                'message': 'User registered successfully'
            }, status=status.HTTP_201_CREATED)
            response.set_cookie(
                key=settings.JWT_AUTH_REFRESH_COOKIE,
                value=str(refresh),
                httponly=True,
                secure=settings.JWT_AUTH_COOKIE_SECURE,
                samesite=settings.JWT_AUTH_COOKIE_SAMESITE
            )
            return response
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = [] # Disable authentication for this view
    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.validated_data['user']
        user_profile = UserProfile.objects.get(user=user)

        ip_address = request.META.get('REMOTE_ADDR')
        log_audit_event(
            user=user,
            action_type='user_login_attempt',
            details=f"Login attempt for user: {user.email}.",
            ip_address=ip_address
        )

        if user_profile.mfa_enabled:
            return Response({"mfa_required": True, "username": user.email}, status=status.HTTP_200_OK)
        else:
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            refresh_token_str = str(refresh)

            log_audit_event(
                user=user,
                action_type='user_login_success_single_factor',
                details=f"User logged in successfully (single-factor).",
                ip_address=ip_address
            )
            response = Response({
                'access': access_token,
                'message': 'Login successful (single-factor)'
            }, status=status.HTTP_200_OK)
            response.set_cookie(
                key=settings.JWT_AUTH_REFRESH_COOKIE,
                value=refresh_token_str,
                httponly=True,
                secure=settings.JWT_AUTH_COOKIE_SECURE,
                samesite=settings.JWT_AUTH_COOKIE_SAMESITE
            )
            return response

    def handle_exception(self, exc):
        if isinstance(exc, AuthenticationFailed):
            ip_address = self.request.META.get('REMOTE_ADDR')
            username_attempted = self.request.data.get('username')

            FailedLoginAttempt.objects.create(
                ip_address=ip_address,
                username_attempted=username_attempted
            )

            now = timezone.now()
            time_window_start = now - datetime.timedelta(minutes=FAILED_LOGIN_WINDOW_MINUTES)
            failed_attempts_count = FailedLoginAttempt.objects.filter(
                ip_address=ip_address,
                timestamp__gte=time_window_start
            ).count()

            if failed_attempts_count >= FAILED_LOGIN_THRESHOLD:
                alert_message = f"Possible brute-force login attempt detected from IP: {ip_address}. Username attempted: '{username_attempted}'. Failed attempts in last {FAILED_LOGIN_WINDOW_MINUTES} minutes: {failed_attempts_count}"
                log_audit_event(
                    user=None,
                    action_type='intrusion_alert',
                    details=alert_message,
                    ip_address=ip_address
                )
                print(f"Intrusion Alert: {alert_message}")

            return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        return super().handle_exception(exc)

class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        log_audit_event(
            user=request.user,
            action_type='user_logout',
            details=f"User logged out.",
            ip_address=request.META.get('REMOTE_ADDR')
        )
        response = Response({"message": "Successfully logged out."}, status=status.HTTP_200_OK)
        response.delete_cookie(
            key=settings.JWT_AUTH_REFRESH_COOKIE,
            path='/api/auth/', # Ensure path matches where cookie is set
            samesite=settings.JWT_AUTH_COOKIE_SAMESITE # Match samesite attribute when deleting
        )
        return response


class UserDeleteView(APIView):
    permission_classes = (IsAuthenticated, IsAdminUser)

    def delete(self, request, user_id):
        user_to_delete = get_object_or_404(User, id=user_id)

        if user_to_delete == request.user:
            return Response({"error": "Admins cannot delete their own accounts via this API."}, status=status.HTTP_400_BAD_REQUEST)
        if user_to_delete.is_superuser:
            return Response({"error": "Cannot delete superuser accounts via this API."}, status=status.HTTP_400_BAD_REQUEST)

        user_to_delete.delete()
        return Response({"message": f"User with ID {user_id} (email: {user_to_delete.email}) deleted successfully."}, status=status.HTTP_204_NO_CONTENT)

class UserListView(APIView):
    permission_classes = (IsAuthenticated, IsAdminUser)

    def get(self, request):
        users = User.objects.all()
        serializer = UserListSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
# @transaction.atomic # Add this decorator
class MFAVerifyView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []  # <--- Add this line to disable authentication
    def post(self, request):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] MFAVerifyView - post method called")

        serializer = MFAVerifySerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            username = serializer.validated_data['username']
            user = get_object_or_404(User, username=username)
            print(f"[{timestamp}] MFAVerifyView - Serializer is valid. Token: {token}, Username: {username}")

            try:
                print(f"[{timestamp}] MFAVerifyView - Attempting to get TOTPAuth object for user: {username}")
                auth = TOTPAuth.objects.get(user=user)
                print(f"[{timestamp}] MFAVerifyView - TOTPAuth object retrieved: {auth}")


                totp = pyotp.TOTP(auth.otp_base32)
                print(f"[{timestamp}] MFAVerifyView - Starting token verification with TOTP object")
                if totp.verify(token):
                    print(f"[{timestamp}] MFAVerifyView - Token Verified Successfully!")

                    print(f"[{timestamp}] MFAVerifyView - Setting auth.otp_enabled = True (before): {auth.otp_enabled}")
                    auth.otp_enabled = True
                    print(f"[{timestamp}] MFAVerifyView - Setting auth.otp_enabled = True (after): {auth.otp_enabled}")

                    print(f"[{timestamp}] MFAVerifyView - Setting auth.otp_verified = True (before): {auth.otp_verified}")
                    auth.otp_verified = True
                    print(f"[{timestamp}] MFAVerifyView - Setting auth.otp_verified = True (after): {auth.otp_verified}")

                    print(f"[{timestamp}] MFAVerifyView - Saving TOTPAuth object...")
                    auth.save()
                    print(f"[{timestamp}] MFAVerifyView - TOTPAuth object saved.")

                    print(f"[{timestamp}] MFAVerifyView - Getting UserProfile for user: {username}")
                    user_profile = UserProfile.objects.get(user=user)
                    print(f"[{timestamp}] MFAVerifyView - UserProfile object retrieved: {user_profile}")

                    print(f"[{timestamp}] MFAVerifyView - Setting user_profile.mfa_enabled = True (before): {user_profile.mfa_enabled}")
                    user_profile.mfa_enabled = True
                    print(f"[{timestamp}] MFAVerifyView - Setting user_profile.mfa_enabled = True (after): {user_profile.mfa_enabled}")

                    print(f"[{timestamp}] MFAVerifyView - Saving UserProfile object...")
                    user_profile.save()
                    print(f"[{timestamp}] MFAVerifyView - UserProfile object saved.")


                    refresh = RefreshToken.for_user(user)
                    access_token = str(refresh.access_token)
                    refresh_token_str = str(refresh)

                    log_audit_event(
                        user=user,
                        action_type='user_login_success_mfa',
                        details=f"User logged in successfully (MFA).",
                        ip_address=request.META.get('REMOTE_ADDR')
                    )
                    print(f"[{timestamp}] MFAVerifyView - Sending 200 OK response")
                    response = Response({
                        'access': access_token,
                        'message': 'MFA token verified successfully'
                    }, status=status.HTTP_200_OK)
                    response.set_cookie(
                        key=settings.JWT_AUTH_REFRESH_COOKIE,
                        value=refresh_token_str,
                        httponly=True,
                        secure=settings.JWT_AUTH_COOKIE_SECURE,
                        samesite=settings.JWT_AUTH_COOKIE_SAMESITE
                    )
                    print(f"[{timestamp}] MFAVerifyView - Response 200 OK sent successfully")
                    return response
                else:
                    print(f"[{timestamp}] MFAVerifyView - Token Verification Failed - Invalid MFA token")
                    log_audit_event(
                        user=user,
                        action_type='mfa_verification_failed',
                        details=f"MFA verification failed for user: {user.email}.",
                        ip_address=request.META.get('REMOTE_ADDR')
                    )
                    return Response({"detail": "Invalid MFA token"}, status=status.HTTP_400_BAD_REQUEST)

            except TOTPAuth.DoesNotExist:
                print(f"[{timestamp}] MFAVerifyView - TOTPAuth.DoesNotExist Exception - TOTP setup not found")
                return Response({"detail": "TOTP setup not found for this user."}, status=status.HTTP_400_BAD_REQUEST)
        else:
            print(f"[{timestamp}] MFAVerifyView - Serializer is NOT valid - Errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
# # Get the original post method
# original_token_refresh_post = SimpleJWTTokenRefreshView.post 

# # Monkey patch the post method with our debug version
# SimpleJWTTokenRefreshView.post = debug_token_refresh_view(original_token_refresh_post)