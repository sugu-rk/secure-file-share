# files/views.py
from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated
from .serializers import FileUploadSerializer, FileShareSerializer, AuditLogSerializer, ShareableLinkSerializer
from django.http import FileResponse
from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated, IsAdminUser, BasePermission
from .models import File, FileSharePermission, AuditLog, ShareableLink, PERMISSION_CHOICES
from django.contrib.auth import get_user_model
from .utils import log_audit_event
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import binascii
from django.core.files.base import ContentFile
from cryptography.fernet import Fernet
from django.conf import settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.permissions import AllowAny # Import AllowAny
from django.contrib.auth.models import Group # Import Group model
from django.http import HttpResponse # Import HttpResponse
import logging # Import logging
import base64 # Import base64
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import padding as crypto_padding

# from cryptography.fernet import Fernet # Import Fernet for key decryption

logger = logging.getLogger(__name__) # Get logger instance


User = get_user_model()
MASTER_ENCRYPTION_KEY = settings.MASTER_ENCRYPTION_KEY_FILES

class FileUploadView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        file_serializer = FileUploadSerializer(data=request.data, context={'request': request})
        if file_serializer.is_valid():
            file_instance = file_serializer.save()
            log_audit_event(
                user=request.user,
                action_type='file_upload',
                file=file_instance,
                details=f"File '{file_instance.filename}' uploaded.",
                ip_address=request.META.get('REMOTE_ADDR')
            )
            return Response(file_serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(file_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class FileListView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        files = File.objects.filter(owner=request.user)
        serializer = FileUploadSerializer(files, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class FileDownloadView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, file_id):
        file_object = get_object_or_404(File, id=file_id)
        logger.debug(f"Download Start - File: {file_object.filename}, ID: {file_id}")

        # Decrypt the server-side AES key.
        f_server = Fernet(MASTER_ENCRYPTION_KEY)
        try:
            encrypted_server_key = file_object.server_encryption_key_base64
            logger.debug(f"Encrypted Server Key Retrieved: {encrypted_server_key[:20]}...")
            encrypted_server_key_bytes = binascii.a2b_base64(encrypted_server_key)
            decrypted_server_key = f_server.decrypt(encrypted_server_key_bytes)
            logger.debug(f"Decrypted Server Key Length: {len(decrypted_server_key)} bytes")
        except Exception as e:
            logger.error(f"Failed to decrypt server key: {e}")
            return Response({"error": "Failed to decrypt file encryption key."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Convert the stored server IV.
        try:
            server_iv_bytes = binascii.unhexlify(file_object.server_iv)
            logger.debug(f"Server IV (bytes): {server_iv_bytes}")
        except Exception as e:
            logger.error(f"Failed to convert server IV: {e}")
            return Response({"error": "Invalid server IV."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Read the encrypted file content.
        try:
            with open(file_object.encrypted_file.path, 'rb') as file_handle:
                server_encrypted_content = file_handle.read()
            logger.debug(f"Read encrypted file content: {len(server_encrypted_content)} bytes")
        except Exception as e:
            logger.error(f"Failed to read encrypted file: {e}")
            return Response({"error": "Could not read file."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Remove server encryption.
        try:
            cipher = Cipher(algorithms.AES(decrypted_server_key), modes.CBC(server_iv_bytes), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_padded = decryptor.update(server_encrypted_content) + decryptor.finalize()
            logger.debug(f"Decrypted padded data length: {len(decrypted_padded)} bytes")
            # Remove PKCS7 padding.
            unpadder = padding.PKCS7(128).unpadder()
            client_encrypted_content = unpadder.update(decrypted_padded) + unpadder.finalize()
            logger.debug(f"Final client-encrypted content length: {len(client_encrypted_content)} bytes")
        except Exception as e:
            logger.error(f"Server decryption failed: {e}")
            return Response({"error": "File decryption failed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Check permission: if request includes ?view=true, fully decrypt the client layer.
        if request.GET.get('view') == 'true':
            try:
                # Fully decrypt the client layer.
                encrypted_client_key = file_object.encryption_key_base64
                logger.debug(f"Encrypted Client Key Retrieved: {encrypted_client_key[:20]}...")
                encrypted_client_key_bytes = binascii.a2b_base64(encrypted_client_key)
                decrypted_client_key_bytes = f_server.decrypt(encrypted_client_key_bytes)
                logger.debug(f"Decrypted Client Key Length: {len(decrypted_client_key_bytes)} bytes")
                # Get the client IV.
                client_iv_bytes = base64.b64decode(file_object.iv_base64)
                client_cipher = Cipher(algorithms.AES(decrypted_client_key_bytes), modes.CBC(client_iv_bytes), backend=default_backend())
                client_decryptor = client_cipher.decryptor()
                client_decrypted_padded = client_decryptor.update(client_encrypted_content) + client_decryptor.finalize()
                client_unpadder = padding.PKCS7(128).unpadder()
                plaintext_content = client_unpadder.update(client_decrypted_padded) + client_unpadder.finalize()
                logger.debug(f"Fully decrypted plaintext content length: {len(plaintext_content)} bytes")
            except Exception as e:
                logger.error(f"Client layer decryption failed: {e}")
                return Response({"error": "Failed to fully decrypt file."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            response = HttpResponse(plaintext_content, content_type='text/plain')
            response['Content-Disposition'] = f'inline; filename="{file_object.filename}"'
        else:
            # Otherwise, return the client-encrypted content along with decryption headers.
            try:
                encrypted_client_key = file_object.encryption_key_base64
                logger.debug(f"Encrypted Client Key Retrieved: {encrypted_client_key[:20]}...")
                encrypted_client_key_bytes = binascii.a2b_base64(encrypted_client_key)
                decrypted_client_key_bytes = f_server.decrypt(encrypted_client_key_bytes)
                decrypted_client_key_base64 = base64.b64encode(decrypted_client_key_bytes).decode()
                logger.debug(f"Decrypted Client Key (Base64): {decrypted_client_key_base64[:20]}...")
            except Exception as e:
                logger.error(f"Client key decryption failed: {e}")
                return Response({"error": "Failed to decrypt client encryption key."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            response = HttpResponse(client_encrypted_content, content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{file_object.filename}"'
            response['X-Encryption-Key'] = decrypted_client_key_base64
            response['X-IV'] = file_object.iv_base64
            logger.debug(f"Download Complete - File '{file_object.filename}' ready for client decryption.")
        return response


class IsAdminGroupUser(BasePermission):
    def has_permission(self, request, view):
        return request.user.groups.filter(name='Admin').exists()

class AdminDashboardView(APIView):
    permission_classes = (IsAuthenticated, IsAdminGroupUser)

    def get(self, request):
        return Response({"message": "Welcome to the Admin Dashboard!"}, status=status.HTTP_200_OK)

class FileShareView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        serializer = FileShareSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            share_results = serializer.save()
            file_id = serializer.validated_data['file_id']
            file_object = File.objects.get(id=file_id)
            shared_emails = serializer.validated_data['shared_with_emails']
            permission_type = serializer.validated_data['permission_type']

            log_audit_event(
                user=request.user,
                action_type='file_share',
                file=file_object,
                details=f"File '{file_object.filename}' shared with emails: {shared_emails}, permission: {permission_type}.",
                ip_address=request.META.get('REMOTE_ADDR')
            )
            return Response({"message": "File sharing initiated", "share_results": share_results}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SharedToMeFilesView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        user = request.user
        share_permissions = FileSharePermission.objects.filter(shared_with_user=user)

        shared_files = []
        for permission in share_permissions:
            file_object = permission.file
            file_data = FileUploadSerializer(file_object).data
            file_data['shared_permission_type'] = permission.permission_type
            shared_files.append(file_data)

        return Response(shared_files, status=status.HTTP_200_OK)

class SharedByMeFilesView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        user = request.user
        owned_files = File.objects.filter(owner=user)

        shared_files_data = []
        for file_object in owned_files:
            share_permissions = FileSharePermission.objects.filter(file=file_object)
            shared_users_permissions = []
            for permission in share_permissions:
                shared_users_permissions.append({
                    'user_email': permission.shared_with_user.email,
                    'permission_type': permission.permission_type
                })

            if shared_users_permissions:
                file_data = FileUploadSerializer(file_object).data
                file_data['shared_with'] = shared_users_permissions
                shared_files_data.append(file_data)

        return Response(shared_files_data, status=status.HTTP_200_OK)

class RevokeAccessView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        file_id = request.data.get('file_id')
        user_email_to_revoke = request.data.get('user_email')

        if not file_id or not user_email_to_revoke:
            return Response({"error": "Both file_id and user_email are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            file_object = File.objects.get(id=file_id, owner=request.user)
        except File.DoesNotExist:
            return Response({"error": "File not found or you are not the owner."}, status=status.HTTP_404_NOT_FOUND)

        try:
            user_to_revoke = User.objects.get(email=user_email_to_revoke)
        except User.DoesNotExist:
            return Response({"error": "User to revoke access from not found."}, status=status.HTTP_404_NOT_FOUND)

        try:
            permission_to_delete = FileSharePermission.objects.get(file=file_object, shared_with_user=user_to_revoke)
            permission_to_delete.delete()
            log_audit_event(
                user=request.user,
                action_type='access_revoke',
                file=file_object,
                details=f"Access revoked for user {user_email_to_revoke} on file '{file_object.filename}'.",
                ip_address=request.META.get('REMOTE_ADDR')
            )
            return Response({"message": f"Access revoked for user {user_email_to_revoke} on file {file_object.filename}"}, status=status.HTTP_200_OK)
        except FileSharePermission.DoesNotExist:
            return Response({"message": f"No sharing permission found for user {user_email_to_revoke} on file {file_object.filename}"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": "Failed to revoke access.", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ModifyPermissionView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        file_id = request.data.get('file_id')
        user_email_to_modify = request.data.get('user_email')
        new_permission_type = request.data.get('permission_type')

        if not file_id or not user_email_to_modify or not new_permission_type:
            return Response({"error": "file_id, user_email, and permission_type are required."}, status=status.HTTP_400_BAD_REQUEST)

        if new_permission_type not in [choice[0] for choice in PERMISSION_CHOICES]:
            return Response({"error": "Invalid permission_type. Choose from: view, download, full."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            file_object = File.objects.get(id=file_id, owner=request.user)
        except File.DoesNotExist:
            return Response({"error": "File not found or you are not the owner."}, status=status.HTTP_404_NOT_FOUND)

        try:
            user_to_modify = User.objects.get(email=user_email_to_modify)
        except User.DoesNotExist:
            return Response({"error": "User to modify permission for not found."}, status=status.HTTP_404_NOT_FOUND)

        try:
            permission_to_modify = FileSharePermission.objects.get(file=file_object, shared_with_user=user_to_modify)
            permission_to_modify.permission_type = new_permission_type
            permission_to_modify.save()
            log_audit_event(
                user=request.user,
                action_type='permission_modified',
                file=file_object,
                details=f"Permission for user {user_email_to_modify} on file '{file_object.filename}' modified to '{new_permission_type}'.",
                ip_address=request.META.get('REMOTE_ADDR')
            )
            return Response({"message": f"Permission for user {user_email_to_modify} on file {file_object.filename} updated to {new_permission_type}."}, status=status.HTTP_200_OK)
        except FileSharePermission.DoesNotExist:
            return Response({"error": f"No sharing permission found for user {user_email_to_modify} on file {file_object.filename}. Share with the user first."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": "Failed to modify permission.", "details": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class AuditLogView(APIView):
    permission_classes = (IsAuthenticated, IsAdminUser)

    def get(self, request):
        audit_logs = AuditLog.objects.all().order_by('-timestamp')
        serializer = AuditLogSerializer(audit_logs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class GenerateShareableLinkView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        serializer = ShareableLinkSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            shareable_link = serializer.save()
            link_url = request.build_absolute_uri(reverse('access-shareable-link', kwargs={'link_uuid': str(shareable_link.link_uuid)}))
            log_audit_event(
                user=request.user,
                action_type='share_link_generated',
                file=shareable_link.file,
                details=f"Shareable link generated for file '{shareable_link.file.filename}' with permission '{shareable_link.permission_type}' and expiration '{shareable_link.expiration_time}'. Link URL: {link_url}",
                ip_address=request.META.get('REMOTE_ADDR')
            )
            return Response({
                'message': 'Shareable link generated successfully',
                'shareable_link_url': link_url,
                'link_uuid': str(shareable_link.link_uuid)
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class AccessFileViaLinkView(APIView):
    permission_classes = [AllowAny]  # Accessible by anyone with the link

    def get(self, request, link_uuid):
        # Retrieve the shareable link record.
        try:
            shareable_link = ShareableLink.objects.get(link_uuid=link_uuid)
        except ShareableLink.DoesNotExist:
            return Response({"error": "Invalid or non-existent shareable link."}, status=status.HTTP_404_NOT_FOUND)

        # Check expiration.
        if shareable_link.expiration_time and shareable_link.expiration_time < timezone.now():
            return Response({"error": "Shareable link has expired."}, status=status.HTTP_403_FORBIDDEN)

        # Get the associated file and permission type.
        file_object = shareable_link.file
        permission_type = shareable_link.permission_type  # e.g., "view" or "download"
        logger.debug(f"AccessFileViaLinkView - Accessing file '{file_object.filename}' via link '{link_uuid}' with permission '{permission_type}'")

        # --- Remove Server Encryption Layer ---
        f_server = Fernet(MASTER_ENCRYPTION_KEY)
        try:
            encrypted_server_key = file_object.server_encryption_key_base64
            logger.debug(f"AccessFileViaLinkView - Encrypted Server Key: {encrypted_server_key[:20]}...")
            encrypted_server_key_bytes = binascii.a2b_base64(encrypted_server_key)
            decrypted_server_key = f_server.decrypt(encrypted_server_key_bytes)
            logger.debug(f"AccessFileViaLinkView - Decrypted Server Key Length: {len(decrypted_server_key)} bytes")
        except Exception as e:
            logger.error(f"AccessFileViaLinkView - Failed to decrypt server key: {e}")
            return Response({"error": "Failed to decrypt file encryption key."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        try:
            server_iv_bytes = binascii.unhexlify(file_object.server_iv)
            logger.debug(f"AccessFileViaLinkView - Server IV (bytes): {server_iv_bytes}")
        except Exception as e:
            logger.error(f"AccessFileViaLinkView - Failed to convert server IV: {e}")
            return Response({"error": "Invalid server IV."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        try:
            with open(file_object.encrypted_file.path, 'rb') as f:
                server_encrypted_content = f.read()
            logger.debug(f"AccessFileViaLinkView - Read encrypted file content: {len(server_encrypted_content)} bytes")
        except Exception as e:
            logger.error(f"AccessFileViaLinkView - Failed to read file: {e}")
            return Response({"error": "Could not read file."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        try:
            cipher = Cipher(algorithms.AES(decrypted_server_key), modes.CBC(server_iv_bytes), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_padded = decryptor.update(server_encrypted_content) + decryptor.finalize()
            logger.debug(f"AccessFileViaLinkView - Decrypted padded data length: {len(decrypted_padded)} bytes")
            unpadder = crypto_padding.PKCS7(128).unpadder()
            client_encrypted_content = unpadder.update(decrypted_padded) + unpadder.finalize()
            logger.debug(f"AccessFileViaLinkView - Client-encrypted content length: {len(client_encrypted_content)} bytes")
        except Exception as e:
            logger.error(f"AccessFileViaLinkView - Server decryption failed: {e}")
            return Response({"error": "File decryption failed."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # --- Fully Decrypt the Client Layer on the Server ---
        try:
            encrypted_client_key = file_object.encryption_key_base64
            logger.debug(f"AccessFileViaLinkView - Encrypted Client Key: {encrypted_client_key[:20]}...")
            encrypted_client_key_bytes = binascii.a2b_base64(encrypted_client_key)
            decrypted_client_key_bytes = f_server.decrypt(encrypted_client_key_bytes)
            logger.debug(f"AccessFileViaLinkView - Decrypted Client Key Length: {len(decrypted_client_key_bytes)} bytes")
        except Exception as e:
            logger.error(f"AccessFileViaLinkView - Client key decryption failed: {e}")
            return Response({"error": "Failed to decrypt client encryption key."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        try:
            client_iv_bytes = base64.b64decode(file_object.iv_base64)
            client_cipher = Cipher(algorithms.AES(decrypted_client_key_bytes), modes.CBC(client_iv_bytes), backend=default_backend())
            client_decryptor = client_cipher.decryptor()
            client_decrypted_padded = client_decryptor.update(client_encrypted_content) + client_decryptor.finalize()
            client_unpadder = crypto_padding.PKCS7(128).unpadder()
            plaintext_content = client_unpadder.update(client_decrypted_padded) + client_unpadder.finalize()
            logger.debug(f"AccessFileViaLinkView - Fully decrypted plaintext length: {len(plaintext_content)} bytes")
        except Exception as e:
            logger.error(f"AccessFileViaLinkView - Client layer decryption failed: {e}")
            return Response({"error": "Failed to fully decrypt file."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # --- Serve the File Based on Permission ---
        if permission_type == "view":
            # For view, serve inline.
            response = HttpResponse(plaintext_content, content_type='text/plain')
            response['Content-Disposition'] = f'inline; filename="{file_object.filename}"'
            logger.debug(f"AccessFileViaLinkView - File '{file_object.filename}' served in view mode (plaintext inline).")
        else:
            # For download (or full), serve as attachment.
            response = HttpResponse(plaintext_content, content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{file_object.filename}"'
            logger.debug(f"AccessFileViaLinkView - File '{file_object.filename}' served for download (plaintext attachment).")
        return response

class AdminFileListAPIView(generics.ListAPIView): # Using generics.ListAPIView for listing
    serializer_class = FileUploadSerializer # Reusing FileUploadSerializer to display file info
    permission_classes = [IsAuthenticated, IsAdminUser] # Admin access only
    queryset = File.objects.all() # Get all files

    def get_queryset(self): # Override get_queryset to allow optional filtering (e.g., by filename - can be added later)
        return File.objects.all() # For now, just return all files - can add filtering logic here later

    def list(self, request, *args, **kwargs): # Override list method for audit logging
        response = super().list(request, *args, **kwargs) # Get default list response
        log_audit_event(
            user=request.user,
            action_type='admin_file_list_viewed', # New audit log action
            details="Admin viewed list of all files.",
            ip_address=request.META.get('REMOTE_ADDR')
        )
        return response


class AdminFileDeleteAPIView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser] # Admin access only

    def delete(self, request, file_id): # Take file_id from URL path
        try:
            file_to_delete = File.objects.get(id=file_id) # Get file by id
        except File.DoesNotExist:
            return Response({"error": "File not found."}, status=status.HTTP_404_NOT_FOUND)

        log_audit_event(
            user=request.user,
            action_type='admin_file_deleted', # New audit log action
            file=file_to_delete, # Log the file being deleted
            details=f"Admin deleted file '{file_to_delete.filename}' (ID: {file_id}).",
            ip_address=request.META.get('REMOTE_ADDR')
        )
        file_to_delete.delete() # Delete the file
        return Response({"message": f"File with ID {file_id} deleted successfully by admin."}, status=status.HTTP_204_NO_CONTENT)