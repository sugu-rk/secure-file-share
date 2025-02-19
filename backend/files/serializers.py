from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import File, FileSharePermission, AuditLog, PERMISSION_CHOICES, ShareableLink
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import secrets
import binascii
from django.core.files.base import ContentFile
from cryptography.fernet import Fernet
from django.conf import settings
import logging

logger = logging.getLogger(__name__) # Get logger instance


User = get_user_model()
MASTER_ENCRYPTION_KEY = settings.MASTER_ENCRYPTION_KEY_FILES

class FileUploadSerializer(serializers.ModelSerializer):
    # Expect the client to send encryptionKey and iv as Base64 strings.
    encryptionKey = serializers.CharField(write_only=True)
    iv = serializers.CharField(write_only=True)

    class Meta:
        model = File
        fields = ('id', 'filename', 'encryptionKey', 'iv')

    def create(self, validated_data):
        # Retrieve the uploaded file.
        file_uploaded = self.context['request'].FILES.get('file')
        filename = validated_data['filename']
        owner = self.context['request'].user
        encryption_key_base64_client = validated_data['encryptionKey']
        iv_base64_client = validated_data['iv']

        logger.debug(f"Upload Start - Filename: {filename}, Owner: {owner}")
        logger.debug(f"Client Key (Base64): {encryption_key_base64_client[:20]}... (length: {len(encryption_key_base64_client)})")
        logger.debug(f"Client IV (Base64): {iv_base64_client}")

        # --- Server-Side Re-Encryption using AES-CBC with PKCS7 Padding ---
        # Generate server-side AES key and IV.
        server_encryption_key = secrets.token_bytes(32)
        server_iv_bytes = secrets.token_bytes(16)
        server_iv_hex = binascii.hexlify(server_iv_bytes).decode()
        logger.debug(f"Server Key Generated (bytes length: {len(server_encryption_key)})")
        logger.debug(f"Server IV (hex): {server_iv_hex}")

        # Read file and log file size.
        file_data = file_uploaded.read()
        logger.debug(f"Original File Size: {len(file_data)} bytes")

        # Pad and encrypt file data.
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        logger.debug(f"Padded File Size: {len(padded_data)} bytes")

        cipher = Cipher(algorithms.AES(server_encryption_key), modes.CBC(server_iv_bytes), backend=default_backend())
        encryptor = cipher.encryptor()
        server_encrypted_file_content = encryptor.update(padded_data) + encryptor.finalize()
        logger.debug(f"Server Encrypted File Size: {len(server_encrypted_file_content)} bytes")

        # Encrypt the client-side AES key.
        f_server = Fernet(MASTER_ENCRYPTION_KEY)
        client_key_bytes = binascii.a2b_base64(encryption_key_base64_client)
        encrypted_client_aes_key_bytes = f_server.encrypt(client_key_bytes)
        encrypted_client_aes_key_base64_stored = binascii.b2a_base64(encrypted_client_aes_key_bytes).decode('utf-8').strip()
        logger.debug(f"Encrypted Client Key Stored (Base64 snippet): {encrypted_client_aes_key_base64_stored[:20]}...")

        # Encrypt the server-side AES key.
        encrypted_server_key_bytes = f_server.encrypt(server_encryption_key)
        encrypted_server_key_base64 = binascii.b2a_base64(encrypted_server_key_bytes).decode('utf-8').strip()
        logger.debug(f"Encrypted Server Key Stored (Base64 snippet): {encrypted_server_key_base64[:20]}...")

        # Create the File instance.
        file_object = File.objects.create(
            owner=owner,
            filename=filename,
            encrypted_file=ContentFile(server_encrypted_file_content, filename),
            encryption_key_base64=encrypted_client_aes_key_base64_stored,
            iv_base64=iv_base64_client,
            server_iv=server_iv_hex,
            server_encryption_key_base64=encrypted_server_key_base64,
        )
        logger.debug(f"FileUploadSerializer - File '{filename}' processed and saved successfully.")
        return file_object
    
class FileShareSerializer(serializers.Serializer):
    file_id = serializers.IntegerField(required=True)
    shared_with_emails = serializers.ListField(child=serializers.EmailField(), required=True)
    permission_type = serializers.ChoiceField(choices=PERMISSION_CHOICES, default='view')

    def validate_file_id(self, value):
        try:
            File.objects.get(id=value, owner=self.context['request'].user)
        except File.DoesNotExist:
            raise serializers.ValidationError("File not found or you are not the owner.")
        return value

    def validate_shared_with_emails(self, value):
        if not value:
            raise serializers.ValidationError("Please provide at least one email to share with.")
        return value

    def create(self, validated_data):
        file_id = validated_data['file_id']
        shared_with_emails = validated_data['shared_with_emails']
        permission_type = validated_data['permission_type']
        file = File.objects.get(id=file_id, owner=self.context['request'].user)

        share_results = []
        for email in shared_with_emails:
            try:
                shared_user = User.objects.get(email=email)
                permission, created = FileSharePermission.objects.get_or_create(
                    file=file,
                    shared_with_user=shared_user,
                    defaults={'permission_type': permission_type}
                )
                if not created:
                    permission.permission_type = permission_type
                    permission.save()
                share_results.append({'email': email, 'status': 'shared', 'permission': permission_type})
            except User.DoesNotExist:
                share_results.append({'email': email, 'status': 'user_not_found'})
            except Exception as e:
                share_results.append({'email': email, 'status': 'error', 'message': str(e)})

        return share_results

class AuditLogSerializer(serializers.ModelSerializer):
    user_email = serializers.SerializerMethodField()

    class Meta:
        model = AuditLog
        fields = ('id', 'timestamp', 'user_email', 'action_type', 'file', 'details', 'ip_address')

    def get_user_email(self, obj):
        if obj.user:
            return obj.user.email
        return None

class ShareableLinkSerializer(serializers.ModelSerializer):
    file_id = serializers.IntegerField(write_only=True)
    permission_type = serializers.ChoiceField(choices=PERMISSION_CHOICES, default='view')
    expiration_time = serializers.DateTimeField(required=False, allow_null=True)

    class Meta:
        model = ShareableLink
        fields = ('id', 'file_id', 'permission_type', 'expiration_time', 'link_uuid', 'created_at')
        read_only_fields = ('link_uuid', 'created_at', 'id')

    def validate_file_id(self, value):
        try:
            File.objects.get(id=value, owner=self.context['request'].user)
        except File.DoesNotExist:
            raise serializers.ValidationError("File not found or you are not the owner.")
        return value

    def create(self, validated_data):
        file_id = validated_data.pop('file_id')
        file = File.objects.get(id=file_id, owner=self.context['request'].user)
        validated_data['file'] = file
        validated_data['created_by'] = self.context['request'].user
        return ShareableLink.objects.create(**validated_data)