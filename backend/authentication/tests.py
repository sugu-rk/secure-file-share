from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from authentication.models import UserProfile
from drf_totp.models import TOTPAuth
import pyotp
import json
from django.conf import settings

User = get_user_model()

class AuthenticationTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.registration_url = reverse('register')
        self.login_url = reverse('login')
        self.logout_url = reverse('logout')
        self.mfa_setup_url = reverse('mfa-setup')
        self.mfa_verify_url = reverse('mfa-verify')
        self.mfa_status_url = reverse('mfa-status')
        self.admin_users_url = reverse('admin-users')

        self.user_credentials = {
            'username': 'testuser@example.com',
            'password': 'Testpassword123!',
            'password2': 'Testpassword123!'
        }
        self.admin_credentials = {
            'username': 'adminuser@example.com',
            'password': 'Adminpassword123!',
            'password2': 'Adminpassword123!'
        }

        self.test_user = User.objects.create_user(username=self.user_credentials['username'], email=self.user_credentials['username'], password=self.user_credentials['password'])
        self.test_user_profile = UserProfile.objects.get(user=self.test_user)

        self.admin_user = User.objects.create_superuser(username=self.admin_credentials['username'], email=self.admin_credentials['username'], password=self.admin_credentials['password'])
        self.admin_user_profile = UserProfile.objects.get(user=self.admin_user)

    def test_user_registration_success(self):
        new_user_data = {
            'username': 'newuser@example.com',
            'password': 'Newpassword123!',
            'password2': 'Newpassword123!'
        }
        response = self.client.post(self.registration_url, new_user_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('access', response.data)
        self.assertEqual(response.data['message'], 'User registered successfully')
        self.assertTrue(User.objects.filter(username=new_user_data['username']).exists())

    def test_user_registration_password_mismatch(self):
        invalid_data = {
            'username': 'newuser2@example.com',
            'password': 'Password123!',
            'password2': 'WrongPassword!'
        }
        response = self.client.post(self.registration_url, invalid_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)

    def test_user_registration_username_exists(self):
        existing_user_data = {
            'username': self.user_credentials['username'],
            'password': 'Newpassword123!',
            'password2': 'Newpassword123!'
        }
        response = self.client.post(self.registration_url, existing_user_data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('username', response.data)

    def test_user_login_success_single_factor(self):
        response = self.client.post(self.login_url, {'username': self.user_credentials['username'], 'password': self.user_credentials['password']})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotIn('refresh', response.data)
        self.assertIn('access', response.data)
        self.assertEqual(response.data['message'], 'Login successful (single-factor)')

    def test_user_login_mfa_required(self):
        self.test_user_profile.mfa_enabled = True
        self.test_user_profile.save()

        response = self.client.post(self.login_url, {'username': self.user_credentials['username'], 'password': self.user_credentials['password']})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['mfa_required'])
        self.assertEqual(response.data['username'], self.user_credentials['username'])
        self.assertNotIn('refresh', response.data)
        self.assertNotIn('access', response.data)

        self.test_user_profile.mfa_enabled = False
        self.test_user_profile.save()

    def test_user_login_invalid_credentials(self):
        response = self.client.post(self.login_url, {'username': self.user_credentials['username'], 'password': 'wrongpassword'})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('detail', response.data)
        self.assertEqual(response.data['detail'], 'Invalid credentials')

    def test_user_logout_success(self):
        login_response = self.client.post(self.login_url, {'username': self.user_credentials['username'], 'password': self.user_credentials['password']})
        access_token = login_response.data['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')

        logout_response = self.client.post(self.logout_url)
        self.assertEqual(logout_response.status_code, status.HTTP_200_OK)
        self.assertEqual(logout_response.data['message'], 'Successfully logged out.')

    def test_mfa_setup_generate_secret(self):
        login_response = self.client.post(self.login_url, {'username': self.user_credentials['username'], 'password': self.user_credentials['password']})
        access_token = login_response.data['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')

        response = self.client.post(self.mfa_setup_url)
        print(f"MFA Setup Response Data: {response.data}") # Debug print
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('secret', response.data)
        self.assertIn('otpauth_url', response.data)
        totp_auth = TOTPAuth.objects.get(user=self.test_user)
        self.assertIsNotNone(totp_auth.otp_base32)
        self.assertIsNotNone(totp_auth.otp_auth_url)

    def test_mfa_verify_success(self):
        login_response = self.client.post(self.login_url, {'username': self.user_credentials['username'], 'password': self.user_credentials['password']})
        access_token = login_response.data['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        mfa_setup_response = self.client.post(self.mfa_setup_url)
        print(f"MFA Setup Response Data in test_mfa_verify_success: {mfa_setup_response.data}") # Debug print
        secret_key = mfa_setup_response.data['secret'] # This line is causing KeyError
        totp = pyotp.TOTP(secret_key)
        valid_otp = totp.now()

        self.client.credentials()
        mfa_verify_data = {'token': valid_otp, 'username': self.user_credentials['username']}
        verify_response = self.client.post(reverse('mfa-verify'), mfa_verify_data)

        self.assertEqual(verify_response.status_code, status.HTTP_200_OK)
        self.assertNotIn('refresh', verify_response.data)
        self.assertIn('access', verify_response.data)
        self.assertEqual(verify_response.data['message'], 'MFA token verified successfully')
        totp_auth = TOTPAuth.objects.get(user=self.test_user)
        self.assertTrue(totp_auth.otp_verified)
        self.assertTrue(totp_auth.otp_enabled)
        self.test_user_profile_reloaded = UserProfile.objects.get(user=self.test_user)
        self.assertTrue(self.test_user_profile_reloaded.mfa_enabled)

    def test_mfa_verify_invalid_token(self):
        login_response = self.client.post(self.login_url, {'username': self.user_credentials['username'], 'password': self.user_credentials['password']})
        access_token = login_response.data['access']
        # self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        self.client.post(self.mfa_setup_url)

        self.client.credentials()
        mfa_verify_data = {'token': '000000', 'username': self.user_credentials['username']}
        verify_response = self.client.post(reverse('mfa-verify'), mfa_verify_data)

        self.assertEqual(verify_response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('detail', verify_response.data)
        self.assertEqual(verify_response.data['detail'], 'Invalid MFA token')
        totp_auth = TOTPAuth.objects.get(user=self.test_user)
        self.assertFalse(totp_auth.otp_verified)
        self.assertFalse(totp_auth.otp_enabled)
        self.test_user_profile_reloaded = UserProfile.objects.get(user=self.test_user)
        self.assertFalse(self.test_user_profile_reloaded.mfa_enabled)

    def test_mfa_verify_no_setup(self):
        self.client.credentials()
        mfa_verify_data = {'token': '123456', 'username': self.user_credentials['username']}
        verify_response = self.client.post(reverse('mfa-verify'), mfa_verify_data)

        self.assertEqual(verify_response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('detail', verify_response.data)
        self.assertEqual(verify_response.data['detail'], 'TOTP setup not found for this user.')

    def test_get_mfa_status_unauthenticated(self):
        response = self.client.get(self.mfa_status_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_get_mfa_status_authenticated(self):
        login_response = self.client.post(self.login_url, {'username': self.user_credentials['username'], 'password': self.user_credentials['password']})
        access_token = login_response.data['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')

        response = self.client.get(self.mfa_status_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('otp_enabled', response.data)
        self.assertIn('otp_verified', response.data)
        self.assertIn('otp_auth_url', response.data)

    def test_admin_user_list_unauthenticated(self):
        response = self.client.get(self.admin_users_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_admin_user_list_non_admin(self):
        login_response = self.client.post(self.login_url, {'username': self.user_credentials['username'], 'password': self.user_credentials['password']})
        access_token = login_response.data['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')

        response = self.client.get(self.admin_users_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_admin_user_list_admin_user(self):
        login_response = self.client.post(self.login_url, {'username': self.admin_credentials['username'], 'password': self.admin_credentials['password']})
        access_token = login_response.data['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')

        response = self.client.get(self.admin_users_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data, list)

    def test_user_login_httponly_refresh_cookie(self):
        response = self.client.post(self.login_url, {'username': self.user_credentials['username'], 'password': self.user_credentials['password']})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertNotIn('refresh', response.data)
        self.assertIn('access', response.data)
        self.assertEqual(response.data['message'], 'Login successful (single-factor)')

        cookies = response.cookies
        self.assertIn(settings.JWT_AUTH_REFRESH_COOKIE, cookies)
        refresh_cookie = cookies[settings.JWT_AUTH_REFRESH_COOKIE]
        self.assertTrue(refresh_cookie['httponly'])
        if settings.JWT_AUTH_COOKIE_SECURE:
            self.assertTrue(refresh_cookie['secure'])
        self.assertEqual(refresh_cookie['samesite'], settings.JWT_AUTH_COOKIE_SAMESITE.lower())

    def test_mfa_verify_httponly_refresh_cookie(self):
        login_response = self.client.post(self.login_url, {'username': self.user_credentials['username'], 'password': self.user_credentials['password']})
        access_token = login_response.data['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        mfa_setup_response = self.client.post(self.mfa_setup_url)
        secret_key = mfa_setup_response.data['secret']
        totp = pyotp.TOTP(secret_key)
        valid_otp = totp.now()

        self.client.credentials()
        mfa_verify_data = {'token': valid_otp, 'username': self.user_credentials['username']}
        verify_response = self.client.post(reverse('mfa-verify'), mfa_verify_data)

        self.assertEqual(verify_response.status_code, status.HTTP_200_OK)
        self.assertNotIn('refresh', verify_response.data)
        self.assertIn('access', verify_response.data)
        self.assertEqual(verify_response.data['message'], 'MFA token verified successfully')

        cookies = verify_response.cookies
        self.assertIn(settings.JWT_AUTH_REFRESH_COOKIE, cookies)
        refresh_cookie = cookies[settings.JWT_AUTH_REFRESH_COOKIE]
        self.assertTrue(refresh_cookie['httponly'])
        if settings.JWT_AUTH_COOKIE_SECURE:
            self.assertTrue(refresh_cookie['secure'])
        self.assertEqual(refresh_cookie['samesite'], settings.JWT_AUTH_COOKIE_SAMESITE.lower())