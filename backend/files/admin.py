from django.contrib import admin
from .models import File, FileSharePermission, AuditLog, FailedLoginAttempt, ShareableLink

# Register your models here.
admin.site.register(File)
admin.site.register(FileSharePermission)
admin.site.register(AuditLog)
admin.site.register(FailedLoginAttempt)
admin.site.register(ShareableLink)