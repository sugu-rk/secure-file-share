from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from files.models import File, FileSharePermission, AuditLog, ShareableLink
from authentication.models import UserProfile
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
import datetime
import uuid
from django.conf import settings
from django.contrib.auth.models import Group  # Import Group model

User = get_user_model()


class FileShareTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.registration_url = reverse('register')
        self.login_url = reverse('login')
        self.logout_url = reverse('logout')
        self.mfa_setup_url = reverse('mfa-setup')
        self.mfa_verify_url = reverse('mfa-verify')
        self.admin_users_url = reverse('admin-users')

        self.file_upload_url = reverse('file-upload')
        self.file_list_url = reverse('my-files')
        self.file_download_url_name = 'file-download'
        self.admin_dashboard_url = reverse('admin-dashboard')
        self.file_share_url = reverse('share-file')
        self.shared_to_me_url = reverse('shared-to-me')
        self.shared_by_me_url = reverse('shared-by-me')
        self.revoke_access_url = reverse('revoke-access')
        self.admin_audit_logs_url = reverse('admin-audit-logs')
        self.generate_share_link_url = reverse('generate-shareable-link')
        self.access_share_link_url_name = 'access-shareable-link'
        self.admin_file_list_url = reverse('admin-file-list')
        self.admin_file_delete_url_name = 'admin-file-delete'

        self.user_credentials = {
            'username': 'testuser@example.com',
            'password': 'Testpassword123!',
        }
        self.admin_credentials = {
            'username': 'adminuser@example.com',
            'password': 'Adminpassword123!',
        }
        self.other_user_credentials = {
            'username': 'otheruser@example.com',
            'password': 'Otherpassword123!',
        }

        self.test_user = User.objects.create_user(username=self.user_credentials['username'], email=self.user_credentials['username'], password=self.user_credentials['password'])
        self.test_user_profile = UserProfile.objects.get(user=self.test_user)
        self.other_user = User.objects.create_user(username=self.other_user_credentials['username'], email=self.other_user_credentials['username'], password=self.other_user_credentials['password'])
        self.other_user_profile = UserProfile.objects.get(user=self.other_user)
        self.admin_user = User.objects.create_superuser(username=self.admin_credentials['username'], email=self.admin_credentials['username'], password=self.admin_credentials['password'])
        self.admin_user_profile = UserProfile.objects.get(user=self.admin_user)
        admin_group, created = Group.objects.get_or_create(name='Admin')
        self.admin_user.groups.add(admin_group)
        self.test_file_content = SimpleUploadedFile("testfile.txt", b"This is a test file content.", content_type="text/plain")
        login_response = self.client.post(self.login_url, {'username': self.user_credentials['username'], 'password': self.user_credentials['password']})
        access_token = login_response.data['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        self.upload_response = self.client.post(self.file_upload_url, {'filename': 'testfile.txt', 'file': self.test_file_content}, format='multipart')

        self.test_file_content_txt = SimpleUploadedFile("testfile.txt", b"This is a test text file.", content_type="text/plain")
        self.test_file_content_pdf = SimpleUploadedFile("testfile.pdf", b"%PDF-1.4\n...", content_type="application/pdf")  # More valid PDF header
        self.test_file_content_jpg = SimpleUploadedFile("testimage.jpg", b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00...', content_type="image/jpeg")  # More valid JPEG header

        # Upload different file types
        self.upload_response_txt = self.client.post(self.file_upload_url, {'filename': 'testfile.txt', 'file': self.test_file_content_txt}, format='multipart')
        self.upload_response_pdf = self.client.post(self.file_upload_url, {'filename': 'testfile.pdf', 'file': self.test_file_content_pdf}, format='multipart')
        self.upload_response_jpg = self.client.post(self.file_upload_url, {'filename': 'testimage.jpg', 'file': self.test_file_content_jpg}, format='multipart')

    def test_file_upload_authenticated(self):
        self.assertEqual(self.upload_response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(File.objects.filter(filename='testfile.txt', owner=self.test_user).exists())

    def test_file_upload_unauthenticated(self):
        client = APIClient()
        response = client.post(self.file_upload_url, {'filename': 'unauth_file.txt', 'file': self.test_file_content}, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_file_list_authenticated(self):
        response = self.client.get(self.file_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 4)  # Modified to 4
        self.assertEqual(response.data[0]['filename'], 'testfile.txt')  # modified to testfile.txt

    def test_file_list_unauthenticated(self):
        client = APIClient()
        response = client.get(self.file_list_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_file_download_owner(self):
        file_id = self.upload_response.data['id']
        download_url = reverse(self.file_download_url_name, kwargs={'file_id': file_id})
        response = self.client.get(download_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Disposition'], f'attachment; filename="testfile.txt"')
        self.assertEqual(response.getvalue().decode('utf-8'), 'This is a test file content.')

    def test_file_download_shared_user_permission(self):
        file_id = self.upload_response.data['id']
        FileSharePermission.objects.create(file_id=file_id, shared_with_user=self.other_user, permission_type='download')

        login_response_other = self.client.post(self.login_url, {'username': self.other_user_credentials['username'], 'password': self.other_user_credentials['password']})
        access_token_other = login_response_other.data['access']
        client_other = APIClient()
        client_other.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token_other}')

        download_url = reverse(self.file_download_url_name, kwargs={'file_id': file_id})
        response_other = client_other.get(download_url)
        self.assertEqual(response_other.status_code, status.HTTP_200_OK)
        self.assertEqual(response_other['Content-Disposition'], f'attachment; filename="testfile.txt"')
        self.assertEqual(response_other.getvalue().decode('utf-8'), 'This is a test file content.')

    def test_file_download_unauthorized(self):
        file_id = self.upload_response.data['id']
        client = APIClient()
        download_url = reverse(self.file_download_url_name, kwargs={'file_id': file_id})
        response = client.get(download_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_file_download_permission_denied(self):
        file_id = self.upload_response.data['id']
        login_response_other = self.client.post(self.login_url, {'username': self.other_user_credentials['username'], 'password': self.other_user_credentials['password']})
        access_token_other = login_response_other.data['access']
        client_other = APIClient()
        client_other.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token_other}')
        download_url = reverse(self.file_download_url_name, kwargs={'file_id': file_id})
        response_other = client_other.get(download_url)
        self.assertEqual(response_other.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response_other.data['error'], 'You do not have permission to download this file.')

    def test_admin_dashboard_access_admin(self):
        login_admin_response = self.client.post(self.login_url, {'username': self.admin_credentials['username'], 'password': self.admin_credentials['password']})
        admin_access_token = login_admin_response.data['access']
        admin_client = APIClient()
        admin_client.credentials(HTTP_AUTHORIZATION=f'Bearer {admin_access_token}')
        response_admin_dash = admin_client.get(self.admin_dashboard_url)
        self.assertEqual(response_admin_dash.status_code, status.HTTP_200_OK)

    def test_admin_dashboard_access_non_admin(self):
        response_non_admin_dash = self.client.get(self.admin_dashboard_url)
        self.assertEqual(response_non_admin_dash.status_code, status.HTTP_403_FORBIDDEN)

    def test_file_share_success(self):
        file_id = self.upload_response.data['id']
        share_data = {
            'file_id': file_id,
            'shared_with_emails': [self.other_user_credentials['username']],
            'permission_type': 'view'
        }
        response_share = self.client.post(self.file_share_url, share_data)
        self.assertEqual(response_share.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response_share.data['message'], 'File sharing initiated')
        self.assertTrue(FileSharePermission.objects.filter(file_id=file_id, shared_with_user=self.other_user, permission_type='view').exists())

    def test_file_share_invalid_file_id(self):
        share_data = {
            'file_id': 999,
            'shared_with_emails': [self.other_user_credentials['username']],
            'permission_type': 'view'
        }
        response_share = self.client.post(self.file_share_url, share_data)
        self.assertEqual(response_share.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('file_id', response_share.data)

    def test_shared_to_me_files_empty(self):
        login_response_other = self.client.post(self.login_url, {'username': self.other_user_credentials['username'], 'password': self.other_user_credentials['password']})
        access_token_other = login_response_other.data['access']
        client_other = APIClient()
        client_other.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token_other}')
        response_shared_to_me = client_other.get(self.shared_to_me_url)
        self.assertEqual(response_shared_to_me.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response_shared_to_me.data), 0)

    def test_shared_to_me_files_list(self):
        file_id = self.upload_response.data['id']
        FileSharePermission.objects.create(file_id=file_id, shared_with_user=self.other_user, permission_type='view')
        login_response_other = self.client.post(self.login_url, {'username': self.other_user_credentials['username'], 'password': self.other_user_credentials['password']})
        access_token_other = login_response_other.data['access']
        client_other = APIClient()
        client_other.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token_other}')
        response_shared_to_me = client_other.get(self.shared_to_me_url)
        self.assertEqual(response_shared_to_me.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response_shared_to_me.data), 1)
        self.assertEqual(response_shared_to_me.data[0]['filename'], 'testfile.txt')

    def test_shared_by_me_files_empty(self):
        response_shared_by_me = self.client.get(self.shared_by_me_url)
        self.assertEqual(response_shared_by_me.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response_shared_by_me.data), 0)

    def test_shared_by_me_files_list(self):
        file_id = self.upload_response.data['id']
        FileSharePermission.objects.create(file_id=file_id, shared_with_user=self.other_user, permission_type='view')
        response_shared_by_me = self.client.get(self.shared_by_me_url)
        self.assertEqual(response_shared_by_me.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response_shared_by_me.data), 1)
        self.assertEqual(response_shared_by_me.data[0]['filename'], 'testfile.txt')
        self.assertEqual(len(response_shared_by_me.data[0]['shared_with']), 1)
        self.assertEqual(response_shared_by_me.data[0]['shared_with'][0]['user_email'], self.other_user_credentials['username'])

    def test_revoke_access_success(self):
        file_id = self.upload_response.data['id']
        FileSharePermission.objects.create(file_id=file_id, shared_with_user=self.other_user, permission_type='view')
        revoke_data = {
            'file_id': file_id,
            'user_email': self.other_user_credentials['username']
        }
        response_revoke = self.client.post(self.revoke_access_url, revoke_data)
        self.assertEqual(response_revoke.status_code, status.HTTP_200_OK)
        self.assertEqual(response_revoke.data['message'], f"Access revoked for user {self.other_user_credentials['username']} on file testfile.txt")
        self.assertFalse(FileSharePermission.objects.filter(file_id=file_id, shared_with_user=self.other_user).exists())

    def test_revoke_access_invalid_file_id(self):
        revoke_data = {
            'file_id': 999,
            'user_email': self.other_user_credentials['username']
        }
        response_revoke = self.client.post(self.revoke_access_url, revoke_data)
        self.assertEqual(response_revoke.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response_revoke.data['error'], 'File not found or you are not the owner.')

    def test_admin_audit_logs_access_admin(self):
        login_admin_response = self.client.post(self.login_url, {'username': self.admin_credentials['username'], 'password': self.admin_credentials['password']})
        admin_access_token = login_admin_response.data['access']
        admin_client = APIClient()
        admin_client.credentials(HTTP_AUTHORIZATION=f'Bearer {admin_access_token}')
        response_audit_logs = admin_client.get(reverse('admin-audit-logs'))
        self.assertEqual(response_audit_logs.status_code, status.HTTP_200_OK)

    def test_admin_audit_logs_access_non_admin(self):
        response_audit_logs = self.client.get(reverse('admin-audit-logs'))
        self.assertEqual(response_audit_logs.status_code, status.HTTP_403_FORBIDDEN)

    def test_generate_shareable_link_authenticated(self):
        login_response = self.client.post(self.login_url, {'username': self.user_credentials['username'], 'password': self.user_credentials['password']})
        access_token = login_response.data['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        upload_response = self.client.post(self.file_upload_url, {'filename': 'testfile.txt', 'file': self.test_file_content}, format='multipart')
        file_id = upload_response.data['id']

        share_link_data = {
            'file_id': file_id,
            'permission_type': 'view'
        }
        response = self.client.post(self.generate_share_link_url, share_link_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('shareable_link_url', response.data)
        self.assertIn('link_uuid', response.data)
        self.assertTrue(ShareableLink.objects.filter(file_id=file_id).exists())
        share_link = ShareableLink.objects.get(file_id=file_id)
        self.assertEqual(str(share_link.link_uuid), response.data['link_uuid'])

    def test_generate_shareable_link_unauthenticated(self):
        self.client.credentials()  # Explicitly clear credentials to ensure unauthenticated request
        response = self.client.post(self.generate_share_link_url, {'file_id': 1, 'permission_type': 'view'})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_access_file_via_shareable_link_valid_link(self):
        login_response = self.client.post(self.login_url, {'username': self.user_credentials['username'], 'password': self.user_credentials['password']})
        access_token = login_response.data['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        # upload_response = self.client.post(self.file_upload_url, {'filename': 'testfile.txt', 'file': self.test_file_content}, format='multipart')
        file_id = self.upload_response.data['id']
        share_link = ShareableLink.objects.create(file_id=file_id, permission_type='download', created_by=self.test_user)

        # self.client.credentials() # REMOVE THIS LINE - Shareable link should be accessed without credentials
        link_uuid_str = str(share_link.link_uuid)
        access_url = reverse(self.access_share_link_url_name, kwargs={'link_uuid': link_uuid_str})
        response = self.client.get(access_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Disposition'], f'attachment; filename="testfile.txt"')
        decoded_content = b''.join(response.streaming_content).decode('utf-8')
        self.assertEqual(decoded_content, 'This is a test file content.')

    def test_access_file_via_shareable_link_invalid_uuid(self):
        invalid_uuid = uuid.uuid4()
        access_url = reverse(self.access_share_link_url_name, kwargs={'link_uuid': invalid_uuid})
        response = self.client.get(access_url)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response.data['error'], 'Invalid or non-existent shareable link.')

    def test_access_file_via_shareable_link_expired_link(self):
        login_response = self.client.post(self.login_url, {'username': self.user_credentials['username'], 'password': self.user_credentials['password']})
        access_token = login_response.data['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        upload_response = self.client.post(self.file_upload_url, {'filename': 'testfile.txt', 'file': self.test_file_content}, format='multipart')
        file_id = upload_response.data['id']
        expired_time = timezone.now() - datetime.timedelta(hours=1)
        share_link = ShareableLink.objects.create(file_id=file_id, permission_type='view', expiration_time=expired_time, created_by=self.test_user)

        # self.client.credentials()
        link_uuid_str = str(share_link.link_uuid)
        access_url = reverse(self.access_share_link_url_name, kwargs={'link_uuid': link_uuid_str})
        response = self.client.get(access_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(response.data['error'], 'Shareable link has expired.')

    def test_access_file_via_shareable_link_wrong_permission(self):
        login_response = self.client.post(self.login_url, {'username': self.user_credentials['username'], 'password': self.user_credentials['password']})
        access_token = login_response.data['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        upload_response = self.client.post(self.file_upload_url, {'filename': 'testfile.txt', 'file': self.test_file_content}, format='multipart')
        file_id = upload_response.data['id']
        share_link = ShareableLink.objects.create(file_id=file_id, permission_type='invalid-permission', created_by=self.test_user)  # Invalid permission type

        # self.client.credentials()
        link_uuid_str = str(share_link.link_uuid)
        access_url = reverse(self.access_share_link_url_name, kwargs={'link_uuid': link_uuid_str})
        response = self.client.get(access_url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)  # Expect 400 now
        self.assertEqual(response.data['error'], 'Invalid permission type for shareable link.')

    def test_file_download_key_decryption_failure(self):
        login_response = self.client.post(self.login_url, {'username': self.user_credentials['username'], 'password': self.user_credentials['password']})
        access_token = login_response.data['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        upload_response = self.client.post(self.file_upload_url, {'filename': 'testfile.txt', 'file': self.test_file_content}, format='multipart')
        file_id = upload_response.data['id']
        file_obj = File.objects.get(id=file_id)

        original_key = file_obj.encryption_key
        file_obj.encryption_key = b"tampered_key_value"
        file_obj.save()

        download_url = reverse(self.file_download_url_name, kwargs={'file_id': file_id})
        response = self.client.get(download_url)
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.data['error'], 'Failed to decrypt file encryption key.')

        file_obj.encryption_key = original_key
        file_obj.save()

    def test_admin_file_list_access_admin(self):
        login_admin_response = self.client.post(self.login_url, {'username': self.admin_credentials['username'], 'password': self.admin_credentials['password']})
        admin_access_token = login_admin_response.data['access']
        admin_client = APIClient()
        admin_client.credentials(HTTP_AUTHORIZATION=f'Bearer {admin_access_token}')
        response_admin_file_list = admin_client.get(self.admin_file_list_url)
        self.assertEqual(response_admin_file_list.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response_admin_file_list.data), 4)  # Modified to 4

    def test_admin_file_list_access_non_admin(self):
        response_admin_file_list = self.client.get(self.admin_file_list_url)
        self.assertEqual(response_admin_file_list.status_code, status.HTTP_403_FORBIDDEN)

    def test_admin_file_delete_admin(self):
        login_admin_response = self.client.post(self.login_url, {'username': self.admin_credentials['username'], 'password': self.admin_credentials['password']})
        admin_access_token = login_admin_response.data['access']
        admin_client = APIClient()
        admin_client.credentials(HTTP_AUTHORIZATION=f'Bearer {admin_access_token}')
        file_id = self.upload_response.data['id']
        admin_file_delete_url = reverse(self.admin_file_delete_url_name, kwargs={'file_id': file_id})
        response_admin_file_delete = admin_client.delete(admin_file_delete_url)
        self.assertEqual(response_admin_file_delete.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(File.objects.filter(id=file_id).exists())  # File should be deleted

    def test_admin_file_delete_non_admin(self):
        file_id = self.upload_response.data['id']
        admin_file_delete_url = reverse(self.admin_file_delete_url_name, kwargs={'file_id': file_id})
        response_admin_file_delete = self.client.delete(admin_file_delete_url)
        self.assertEqual(response_admin_file_delete.status_code, status.HTTP_403_FORBIDDEN)

    def test_admin_file_delete_invalid_file_id(self):
        login_admin_response = self.client.post(self.login_url, {'username': self.admin_credentials['username'], 'password': self.admin_credentials['password']})
        admin_access_token = login_admin_response.data['access']
        admin_client = APIClient()
        admin_client.credentials(HTTP_AUTHORIZATION=f'Bearer {admin_access_token}')
        invalid_file_id = 999
        admin_file_delete_url = reverse(self.admin_file_delete_url_name, kwargs={'file_id': invalid_file_id})
        response_admin_file_delete = admin_client.delete(admin_file_delete_url)
        self.assertEqual(response_admin_file_delete.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response_admin_file_delete.data['error'], 'File not found.')

    def test_modify_permission_success(self):
        file_id = self.upload_response.data['id']
        FileSharePermission.objects.create(file_id=file_id, shared_with_user=self.other_user, permission_type='view')
        modify_data = {
            'file_id': file_id,
            'user_email': self.other_user_credentials['username'],
            'permission_type': 'download'  # Change to download
        }
        response_modify = self.client.post(reverse('modify-permission'), modify_data)
        self.assertEqual(response_modify.status_code, status.HTTP_200_OK)
        self.assertEqual(response_modify.data['message'], f"Permission for user {self.other_user_credentials['username']} on file testfile.txt updated to download.")
        updated_permission = FileSharePermission.objects.get(file_id=file_id, shared_with_user=self.other_user)
        self.assertEqual(updated_permission.permission_type, 'download')  # Verify permission changed

    def test_modify_permission_invalid_file_id(self):
        modify_data = {
            'file_id': 999,  # Invalid file ID
            'user_email': self.other_user_credentials['username'],
            'permission_type': 'download'
        }
        response_modify = self.client.post(reverse('modify-permission'), modify_data)
        self.assertEqual(response_modify.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response_modify.data['error'], 'File not found or you are not the owner.')

    def test_modify_permission_user_not_shared_with(self):
        file_id = self.upload_response.data['id']
        modify_data = {
            'file_id': file_id,
            'user_email': self.other_user_credentials['username'],  # User not initially shared with
            'permission_type': 'download'
        }
        response_modify = self.client.post(reverse('modify-permission'), modify_data)
        self.assertEqual(response_modify.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response_modify.data['error'], f"No sharing permission found for user {self.other_user_credentials['username']} on file testfile.txt. Share with the user first.")

    def test_modify_permission_invalid_permission_type(self):
        file_id = self.upload_response.data['id']
        FileSharePermission.objects.create(file_id=file_id, shared_with_user=self.other_user, permission_type='view')
        modify_data = {
            'file_id': file_id,
            'user_email': self.other_user_credentials['username'],
            'permission_type': 'invalid-permission'  # Invalid permission type
        }
        response_modify = self.client.post(reverse('modify-permission'), modify_data)
        self.assertEqual(response_modify.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response_modify.data['error'], 'Invalid permission_type. Choose from: view, download, full.')

    def test_modify_permission_missing_parameters(self):
        file_id = self.upload_response.data['id']
        FileSharePermission.objects.create(file_id=file_id, shared_with_user=self.other_user, permission_type='view')

        # Missing user_email
        modify_data_missing_email = {'file_id': file_id, 'permission_type': 'download'}
        response_missing_email = self.client.post(reverse('modify-permission'), modify_data_missing_email)
        self.assertEqual(response_missing_email.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response_missing_email.data)

        # Missing permission_type
        modify_data_missing_permission = {'file_id': file_id, 'user_email': self.other_user_credentials['username']}
        response_missing_permission = self.client.post(reverse('modify-permission'), modify_data_missing_permission)
        self.assertEqual(response_missing_permission.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response_missing_permission.data)

    def test_access_file_via_shareable_link_view_permission_txt(self):
        file_id = self.upload_response_txt.data['id']
        share_link = ShareableLink.objects.create(file_id=file_id, permission_type='view', created_by=self.test_user)
        link_uuid_str = str(share_link.link_uuid)
        access_url = reverse(self.access_share_link_url_name, kwargs={'link_uuid': link_uuid_str})
        response = self.client.get(access_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Disposition'], f'inline; filename="testfile.txt"')  # Expect inline
        self.assertEqual(response['Content-Type'], 'text/plain')  # Expect text/plain
        decoded_content = response.content.decode('utf-8')
        self.assertEqual(decoded_content, 'This is a test text file.')

    def test_access_file_via_shareable_link_view_permission_pdf(self):
        file_id = self.upload_response_pdf.data['id']
        share_link = ShareableLink.objects.create(file_id=file_id, permission_type='view', created_by=self.test_user)
        link_uuid_str = str(share_link.link_uuid)
        access_url = reverse(self.access_share_link_url_name, kwargs={'link_uuid': link_uuid_str})
        response = self.client.get(access_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Disposition'], f'inline; filename="testfile.pdf"')  # Expect inline
        self.assertEqual(response['Content-Type'], 'application/pdf')  # Expect application/pdf
        decoded_content = response.content  # content is in bytes
        # We can't fully validate PDF content in a simple test, but ensure it's not empty
        self.assertTrue(len(decoded_content) > 10)  # Check for some content

    def test_access_file_via_shareable_link_view_permission_jpg(self):
        file_id = self.upload_response_jpg.data['id']
        share_link = ShareableLink.objects.create(file_id=file_id, permission_type='view', created_by=self.test_user)
        link_uuid_str = str(share_link.link_uuid)
        access_url = reverse(self.access_share_link_url_name, kwargs={'link_uuid': link_uuid_str})
        response = self.client.get(access_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Disposition'], f'inline; filename="testimage.jpg"')  # Expect inline
        self.assertTrue(response['Content-Type'] in ['image/jpeg', 'image/jpg'])  # Expect image/jpeg or image/jpg
        decoded_content = response.content  # content is in bytes
        # We can't fully validate image content, but ensure it's not empty
        self.assertTrue(len(decoded_content) > 10)  # Check for some content

    def test_access_file_via_shareable_link_download_permission_txt(self):
        file_id = self.upload_response_txt.data['id']
        share_link = ShareableLink.objects.create(file_id=file_id, permission_type='download', created_by=self.test_user)
        link_uuid_str = str(share_link.link_uuid)
        access_url = reverse(self.access_share_link_url_name, kwargs={'link_uuid': link_uuid_str})
        response = self.client.get(access_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Disposition'], f'attachment; filename="testfile.txt"')  # Expect attachment
        self.assertEqual(response['Content-Type'], 'application/octet-stream')  # Expect binary stream for download
        decoded_content = b''.join(response.streaming_content).decode('utf-8')
        self.assertEqual(decoded_content, 'This is a test text file.')

    def test_access_file_via_shareable_link_download_permission_pdf(self):
        file_id = self.upload_response_pdf.data['id']
        share_link = ShareableLink.objects.create(file_id=file_id, permission_type='download', created_by=self.test_user)
        link_uuid_str = str(share_link.link_uuid)
        access_url = reverse(self.access_share_link_url_name, kwargs={'link_uuid': link_uuid_str})
        response = self.client.get(access_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Disposition'], f'attachment; filename="testfile.pdf"')  # Expect attachment
        self.assertEqual(response['Content-Type'], 'application/octet-stream')  # Expect binary stream
        decoded_content = b''.join(response.streaming_content).decode('utf-8')
        # We can't fully validate PDF content in a simple test, but ensure it's not empty
        self.assertTrue(len(decoded_content) > 10)  # Check for some content

    def test_access_file_via_shareable_link_download_permission_jpg(self):
        file_id = self.upload_response_jpg.data['id']
        share_link = ShareableLink.objects.create(file_id=file_id, permission_type='download', created_by=self.test_user)
        link_uuid_str = str(share_link.link_uuid)
        access_url = reverse(self.access_share_link_url_name, kwargs={'link_uuid': link_uuid_str})
        response = self.client.get(access_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Disposition'], f'attachment; filename="testimage.jpg"')  # Expect attachment
        self.assertEqual(response['Content-Type'], 'application/octet-stream')  # Expect binary stream
        decoded_content = response.streaming_content  # Use streaming_content for FileResponse
        # We can't fully validate image content, but ensure it's not empty
        self.assertTrue(len(decoded_content) > 10)  # Check for some content

    def test_access_file_via_shareable_link_full_permission_txt(self):  # Test full permission (currently download)
        file_id = self.upload_response_txt.data['id']
        share_link = ShareableLink.objects.create(file_id=file_id, permission_type='full', created_by=self.test_user)
        link_uuid_str = str(share_link.link_uuid)
        access_url = reverse(self.access_share_link_url_name, kwargs={'link_uuid': link_uuid_str})
        response = self.client.get(access_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Disposition'], f'attachment; filename="testfile.txt"')  # Expect attachment (full is download now)
        self.assertEqual(response['Content-Type'], 'application/octet-stream')  # Expect binary stream
        decoded_content = b''.join(response.streaming_content).decode('utf-8')
        self.assertEqual(decoded_content, 'This is a test text file.')

    def test_access_file_via_shareable_link_wrong_permission(self):
        login_response = self.client.post(self.login_url, {'username': self.user_credentials['username'], 'password': self.user_credentials['password']})
        access_token = login_response.data['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        upload_response = self.client.post(self.file_upload_url, {'filename': 'testfile.txt', 'file': self.test_file_content}, format='multipart')
        file_id = upload_response.data['id']
        share_link = ShareableLink.objects.create(file_id=file_id, permission_type='invalid-permission', created_by=self.test_user)  # Invalid permission type

        # self.client.credentials()
        link_uuid_str = str(share_link.link_uuid)
        access_url = reverse(self.access_share_link_url_name, kwargs={'link_uuid': link_uuid_str})
        response = self.client.get(access_url)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)  # Expect 400 now
        self.assertEqual(response.data['error'], 'Invalid permission type for shareable link.')

    def test_file_download_key_decryption_failure(self):
        login_response = self.client.post(self.login_url, {'username': self.user_credentials['username'], 'password': self.user_credentials['password']})
        access_token = login_response.data['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        upload_response = self.client.post(self.file_upload_url, {'filename': 'testfile.txt', 'file': self.test_file_content}, format='multipart')
        file_id = upload_response.data['id']
        file_obj = File.objects.get(id=file_id)

        original_key = file_obj.encryption_key
        file_obj.encryption_key = b"tampered_key_value"
        file_obj.save()

        download_url = reverse(self.file_download_url_name, kwargs={'file_id': file_id})
        response = self.client.get(download_url)
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
        self.assertEqual(response.data['error'], 'Failed to decrypt file encryption key.')

        file_obj.encryption_key = original_key
        file_obj.save()

    def test_admin_file_list_access_admin(self):
        login_admin_response = self.client.post(self.login_url, {'username': self.admin_credentials['username'], 'password': self.admin_credentials['password']})
        admin_access_token = login_admin_response.data['access']
        admin_client = APIClient()
        admin_client.credentials(HTTP_AUTHORIZATION=f'Bearer {admin_access_token}')
        response_admin_file_list = admin_client.get(self.admin_file_list_url)
        self.assertEqual(response_admin_file_list.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response_admin_file_list.data), 4)  # Modified to 4

    def test_admin_file_list_access_non_admin(self):
        response_admin_file_list = self.client.get(self.admin_file_list_url)
        self.assertEqual(response_admin_file_list.status_code, status.HTTP_403_FORBIDDEN)

    def test_admin_file_delete_admin(self):
        login_admin_response = self.client.post(self.login_url, {'username': self.admin_credentials['username'], 'password': self.admin_credentials['password']})
        admin_access_token = login_admin_response.data['access']
        admin_client = APIClient()
        admin_client.credentials(HTTP_AUTHORIZATION=f'Bearer {admin_access_token}')
        file_id = self.upload_response.data['id']
        admin_file_delete_url = reverse(self.admin_file_delete_url_name, kwargs={'file_id': file_id})
        response_admin_file_delete = admin_client.delete(admin_file_delete_url)
        self.assertEqual(response_admin_file_delete.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(File.objects.filter(id=file_id).exists())  # File should be deleted

    def test_admin_file_delete_non_admin(self):
        file_id = self.upload_response.data['id']
        admin_file_delete_url = reverse(self.admin_file_delete_url_name, kwargs={'file_id': file_id})
        response_admin_file_delete = self.client.delete(admin_file_delete_url)
        self.assertEqual(response_admin_file_delete.status_code, status.HTTP_403_FORBIDDEN)

    def test_admin_file_delete_invalid_file_id(self):
        login_admin_response = self.client.post(self.login_url, {'username': self.admin_credentials['username'], 'password': self.admin_credentials['password']})
        admin_access_token = login_admin_response.data['access']
        admin_client = APIClient()
        admin_client.credentials(HTTP_AUTHORIZATION=f'Bearer {admin_access_token}')
        invalid_file_id = 999
        admin_file_delete_url = reverse(self.admin_file_delete_url_name, kwargs={'file_id': invalid_file_id})
        response_admin_file_delete = admin_client.delete(admin_file_delete_url)
        self.assertEqual(response_admin_file_delete.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response_admin_file_delete.data['error'], 'File not found.')

    def test_modify_permission_success(self):
        file_id = self.upload_response.data['id']
        FileSharePermission.objects.create(file_id=file_id, shared_with_user=self.other_user, permission_type='view')
        modify_data = {
            'file_id': file_id,
            'user_email': self.other_user_credentials['username'],
            'permission_type': 'download'  # Change to download
        }
        response_modify = self.client.post(reverse('modify-permission'), modify_data)
        self.assertEqual(response_modify.status_code, status.HTTP_200_OK)
        self.assertEqual(response_modify.data['message'], f"Permission for user {self.other_user_credentials['username']} on file testfile.txt updated to download.")
        updated_permission = FileSharePermission.objects.get(file_id=file_id, shared_with_user=self.other_user)
        self.assertEqual(updated_permission.permission_type, 'download')  # Verify permission changed

    def test_modify_permission_invalid_file_id(self):
        modify_data = {
            'file_id': 999,  # Invalid file ID
            'user_email': self.other_user_credentials['username'],
            'permission_type': 'download'
        }
        response_modify = self.client.post(reverse('modify-permission'), modify_data)
        self.assertEqual(response_modify.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response_modify.data['error'], 'File not found or you are not the owner.')

    def test_modify_permission_user_not_shared_with(self):
        file_id = self.upload_response.data['id']
        modify_data = {
            'file_id': file_id,
            'user_email': self.other_user_credentials['username'],  # User not initially shared with
            'permission_type': 'download'
        }
        response_modify = self.client.post(reverse('modify-permission'), modify_data)
        self.assertEqual(response_modify.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual(response_modify.data['error'], f"No sharing permission found for user {self.other_user_credentials['username']} on file testfile.txt. Share with the user first.")

    def test_modify_permission_invalid_permission_type(self):
        file_id = self.upload_response.data['id']
        FileSharePermission.objects.create(file_id=file_id, shared_with_user=self.other_user, permission_type='view')
        modify_data = {
            'file_id': file_id,
            'user_email': self.other_user_credentials['username'],
            'permission_type': 'invalid-permission'  # Invalid permission type
        }
        response_modify = self.client.post(reverse('modify-permission'), modify_data)
        self.assertEqual(response_modify.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response_modify.data['error'], 'Invalid permission_type. Choose from: view, download, full.')

    def test_modify_permission_missing_parameters(self):
        file_id = self.upload_response.data['id']
        FileSharePermission.objects.create(file_id=file_id, shared_with_user=self.other_user, permission_type='view')

        # Missing user_email
        modify_data_missing_email = {'file_id': file_id, 'permission_type': 'download'}
        response_missing_email = self.client.post(reverse('modify-permission'), modify_data_missing_email)
        self.assertEqual(response_missing_email.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response_missing_email.data)

        # Missing permission_type
        modify_data_missing_permission = {'file_id': file_id, 'user_email': self.other_user_credentials['username']}
        response_missing_permission = self.client.post(reverse('modify-permission'), modify_data_missing_permission)
        self.assertEqual(response_missing_permission.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response_missing_permission.data)

    def test_access_file_via_shareable_link_view_permission_txt(self):
        file_id = self.upload_response_txt.data['id']
        share_link = ShareableLink.objects.create(file_id=file_id, permission_type='view', created_by=self.test_user)
        link_uuid_str = str(share_link.link_uuid)
        access_url = reverse(self.access_share_link_url_name, kwargs={'link_uuid': link_uuid_str})
        response = self.client.get(access_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Disposition'], f'inline; filename="testfile.txt"')  # Expect inline
        self.assertEqual(response['Content-Type'], 'text/plain')  # Expect text/plain
        decoded_content = response.content.decode('utf-8')
        self.assertEqual(decoded_content, 'This is a test text file.')

    def test_access_file_via_shareable_link_view_permission_pdf(self):
        file_id = self.upload_response_pdf.data['id']
        share_link = ShareableLink.objects.create(file_id=file_id, permission_type='view', created_by=self.test_user)
        link_uuid_str = str(share_link.link_uuid)
        access_url = reverse(self.access_share_link_url_name, kwargs={'link_uuid': link_uuid_str})
        response = self.client.get(access_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Disposition'], f'inline; filename="testfile.pdf"')  # Expect inline
        self.assertEqual(response['Content-Type'], 'application/pdf')  # Expect application/pdf
        decoded_content = response.content  # content is in bytes
        # We can't fully validate PDF content in a simple test, but ensure it's not empty
        self.assertTrue(len(decoded_content) > 10)  # Check for some content

    def test_access_file_via_shareable_link_view_permission_jpg(self):
        file_id = self.upload_response_jpg.data['id']
        share_link = ShareableLink.objects.create(file_id=file_id, permission_type='view', created_by=self.test_user)
        link_uuid_str = str(share_link.link_uuid)
        access_url = reverse(self.access_share_link_url_name, kwargs={'link_uuid': link_uuid_str})
        response = self.client.get(access_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Disposition'], f'inline; filename="testimage.jpg"')  # Expect inline
        self.assertTrue(response['Content-Type'] in ['image/jpeg', 'image/jpg'])  # Expect image/jpeg or image/jpg
        decoded_content = response.content  # content is in bytes
        # We can't fully validate image content, but ensure it's not empty
        self.assertTrue(len(decoded_content) > 10)  # Check for some content

    def test_access_file_via_shareable_link_download_permission_txt(self):
        file_id = self.upload_response_txt.data['id']
        share_link = ShareableLink.objects.create(file_id=file_id, permission_type='download', created_by=self.test_user)
        link_uuid_str = str(share_link.link_uuid)
        access_url = reverse(self.access_share_link_url_name, kwargs={'link_uuid': link_uuid_str})
        response = self.client.get(access_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Disposition'], f'attachment; filename="testfile.txt"')  # Expect attachment
        self.assertEqual(response['Content-Type'], 'application/octet-stream')  # Expect binary stream for download
        decoded_content = b''.join(response.streaming_content).decode('utf-8')
        self.assertEqual(decoded_content, 'This is a test text file.')

    def test_access_file_via_shareable_link_download_permission_pdf(self):
        file_id = self.upload_response_pdf.data['id']
        share_link = ShareableLink.objects.create(file_id=file_id, permission_type='download', created_by=self.test_user)
        link_uuid_str = str(share_link.link_uuid)
        access_url = reverse(self.access_share_link_url_name, kwargs={'link_uuid': link_uuid_str})
        response = self.client.get(access_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Disposition'], f'attachment; filename="testfile.pdf"')  # Expect attachment
        self.assertEqual(response['Content-Type'], 'application/octet-stream')  # Expect binary stream
        decoded_content = b''.join(response.streaming_content).decode('utf-8')
        # We can't fully validate PDF content in a simple test, but ensure it's not empty
        self.assertTrue(len(decoded_content) > 10)  # Check for some content

    def test_access_file_via_shareable_link_download_permission_jpg(self):
        file_id = self.upload_response_jpg.data['id']
        share_link = ShareableLink.objects.create(file_id=file_id, permission_type='download', created_by=self.test_user)
        link_uuid_str = str(share_link.link_uuid)
        access_url = reverse(self.access_share_link_url_name, kwargs={'link_uuid': link_uuid_str})
        response = self.client.get(access_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Disposition'], f'attachment; filename="testimage.jpg"')  # Expect attachment
        self.assertEqual(response['Content-Type'], 'application/octet-stream')  # Expect binary stream
        decoded_content = response.streaming_content  # Use streaming_content for FileResponse - Corrected line
        # We can't fully validate image content, but ensure it's not empty
        self.assertTrue(len(decoded_content) > 10)  # Check for some content

    def test_access_file_via_shareable_link_full_permission_txt(self):  # Test full permission (currently download)
        file_id = self.upload_response_txt.data['id']
        share_link = ShareableLink.objects.create(file_id=file_id, permission_type='full', created_by=self.test_user)
        link_uuid_str = str(share_link.link_uuid)
        access_url = reverse(self.access_share_link_url_name, kwargs={'link_uuid': link_uuid_str})
        response = self.client.get(access_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Disposition'], f'attachment; filename="testfile.txt"')  # Expect attachment (full is download now)
        self.assertEqual(response['Content-Type'], 'application/octet-stream')  # Expect binary stream
        decoded_content = b''.join(response.streaming_content).decode('utf-8')
        self.assertEqual(decoded_content, 'This is a test text file.')