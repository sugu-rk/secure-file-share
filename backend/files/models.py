from django.db import models
from django.conf import settings
import uuid
from django.utils import timezone


class File(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    filename = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    encrypted_file = models.FileField(upload_to='encrypted_uploads/', blank=True, null=True)
    # This is the encrypted client key (encrypted with our master key)
    encryption_key_base64 = models.TextField(blank=True, null=True)
    iv_base64 = models.CharField(max_length=255, blank=True, null=True)
    # The server’s IV (for its own encryption layer), stored as a hex string.
    server_iv = models.CharField(max_length=255, blank=True, null=True)
    # NEW: The server-side AES key (encrypted with the master key)
    server_encryption_key_base64 = models.TextField(blank=True, null=True)

PERMISSION_CHOICES = [
    ('view', 'View Only'),
    ('download', 'Download'),
    ('full', 'Full Access'),
]

class FileSharePermission(models.Model):
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='shared_permissions')
    shared_with_user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='file_permissions')
    permission_type = models.CharField(max_length=10, choices=PERMISSION_CHOICES, default='view')

    class Meta:
        unique_together = ('file', 'shared_with_user')

    def __str__(self):
        return f"Permission: {self.permission_type} for {self.shared_with_user} on {self.file.filename}"

LOG_ACTION_CHOICES = [
    ('file_upload', 'File Upload'),
    ('file_download', 'File Download'),
    ('file_share', 'File Share'),
    ('access_revoke', 'Access Revoke'),
    ('user_login', 'User Login'),
    ('user_register', 'User Registration'),
    ('intrusion_alert', 'Intrusion Alert'),
    ('share_link_generated', 'Share Link Generated'),
    ('file_download_share_link', 'File Download via Share Link'),
    ('admin_file_list_viewed', 'Admin Viewed File List'), 
    ('admin_file_deleted', 'Admin Deleted File'), 
]

class AuditLog(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    action_type = models.CharField(max_length=30, choices=LOG_ACTION_CHOICES)
    file = models.ForeignKey(File, on_delete=models.SET_NULL, null=True, blank=True)
    details = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    def __str__(self):
        return f"{self.timestamp} - {self.action_type} by {self.user}"

class FailedLoginAttempt(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()
    username_attempted = models.CharField(max_length=255, blank=True)

    def __str__(self):
        return f"{self.timestamp} - Failed login from {self.ip_address} for user '{self.username_attempted}'"

class ShareableLink(models.Model):
    file = models.ForeignKey(File, on_delete=models.CASCADE, related_name='share_links')
    link_uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    permission_type = models.CharField(max_length=10, choices=PERMISSION_CHOICES, default='view')
    expiration_time = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    encryption_key = models.BinaryField(blank=True, null=True)
    encryption_key_base64 = models.TextField(blank=True, null=True) # Stores Fernet-encrypted client-side key (base64)
    iv_base64 = models.CharField(max_length=255, blank=True, null=True) # Stores client-side IV (base64)

    def __str__(self):
        return f"Shareable Link for {self.file.filename} - Permission: {self.permission_type} - Expires: {self.expiration_time}"